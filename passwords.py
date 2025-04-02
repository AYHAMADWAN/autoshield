import os
import sys
import remote
from rich import print

SECURITY_RULES = [
    {
        'module': 'pam_unix.so',
        'types': ['password'],
        'required_params': {'sha512': None},
        'forbidden_params': ['nullok'],
        'message': 'Use SHA512 hashing and do not allow empty passwords in the password module.'
    },
    {
        'module': 'pam_pwquality.so',
        'types': ['password'],
        'required_params': {
            'minlen': '14',
            'dcredit': '-1',
            'ucredit': '-1',
            'ocredit': '-1',
            'lcredit': '-1'
        },
        'message': 'Enforce password complexity: minlen=14 and require at least one of each character type.'
    },
    {
        'module': 'pam_faillock.so',
        'types': ['auth'],
        'required_params': {
            'deny': '5',
            'unlock_time': '1800'
        },
        'message': 'Account lockout after 5 failed attempts (unlock for 1800 seconds).'
    },
    {
        'module': 'pam_tally2.so',
        'types': ['auth'],
        'required_params': {
            'deny': '5',
            'unlock_time': '1800'
        },
        'message': 'Account lockout after 5 failed attempts (unlock for 1800 seconds).'
    },
    {
        'module': 'pam_wheel.so',
        'types': ['auth'],
        'required_params': {'use_uid': None},
        'message': 'Restrict "su" access to the wheel group.'
    }
]

def report(types, value1, value2, value3, value4):
    if types == 'password':
        print(f"""[red][PASSWORD][/red] [#f01f23]{value1}[/#f01f23]
    [cyan]File:[/cyan]    [#990fbf]{os.path.dirname(value2)}/[/#990fbf][#c31ff0]{os.path.basename(value2)}[/#c31ff0]
    [cyan]Line:[/cyan]    [#1fc6f0]{value3}[/#1fc6f0]
    [cyan]Details:[/cyan] [#f0ae1f]{value4}[/#f0ae1f]\n\n""")

    elif types == 'misconfig':
        print(f"""[red][MISCONFIG][/red] [#f01f23]{value1}[/#f01f23]
    [cyan]File:[/cyan]    [#990fbf]{os.path.dirname(value2)}/[/#990fbf][#c31ff0]{os.path.basename(value2)}[/#c31ff0]
    [cyan]Key:[/cyan]     [#1fc6f0]{value3}[/#1fc6f0]
    [cyan]Details:[/cyan] [#f0ae1f]{value4}[/#f0ae1f]\n\n""")
        

def parse_pam_line(line, is_pam_conf):
    """ PARSE A LINE FROM PAM CONFIG FILE """
    parts = line.strip().split()
    if not parts or parts[0].startswith('#'):
        return None
    
    # Handle multiple items inside []
    merged_parts = []
    inside_brackets = None
    for part in parts:
        if part.startswith('['):
            inside_brackets = []
            inside_brackets.append(part.strip('['))
        elif part.endswith(']'):
            inside_brackets.append(part.strip(']'))
            merged_parts.append(inside_brackets)
            inside_brackets = None
        elif inside_brackets is not None:
            inside_brackets.append(part)
        else:
            merged_parts.append(part)
    parts = merged_parts
    
    if is_pam_conf:
        if len(parts) < 4:
            return None
        service, type_, control, module = parts[0], parts[1], parts[2], parts[3]
        args = parts[4:]
    else:
        if len(parts) < 3:
            return None
        service = None
        type_, control, module = parts[0], parts[1], parts[2]
        args = parts[3:]
    
    # Get module name from path
    module_name = os.path.basename(module)
    
    return {
        'service': service,
        'type': type_,
        'control': control,
        'module': module_name,
        'args': args
    }

def get_pam_file_issues(file, is_pam_conf, filepath):
    issues = []
    for line_num, line in enumerate(file, 1):
        parsed = parse_pam_line(line, is_pam_conf)
        if not parsed:
            continue

        service = parsed['service'] if is_pam_conf else os.path.basename(filepath)
        type_ = parsed['type']
        control = parsed['control']
        module = parsed['module']
        args = parsed['args']

        #print(filepath)
        #print(f'service: {service}, type_:{type_}, control:{control}, module:{module}, args:{args}')
        
        params = {}
        for arg in args:
            if '=' in arg:
                key, value = arg.split('=', 1)
                params[key] = value
            else:
                params[arg] = None

        # Check security rules
        for rule in SECURITY_RULES:
            if module != rule['module']:
                continue
            if 'types' in rule and type_ not in rule['types']:
                continue

            # Check required params
            required = rule.get('required_params', {})
            for param, expected in required.items():
                if param not in params:
                    issues.append({
                        'file': filepath,
                        'line': line_num,
                        'details': rule['message'],
                        'message': f'Missing required parameter: {param}'
                    })
                elif expected is not None and params[param] != expected:
                    issues.append({
                        'file': filepath,
                        'line': line_num,
                        'details': rule['message'],
                        'message': f'Incorrect value for {param}, expected: {expected}'
                    })

            # Check forbidden params
            forbidden = rule.get('forbidden_params', [])
            for param in forbidden:
                if param in params:
                    issues.append({
                        'file': filepath,
                        'line': line_num,
                        'details': rule['message'],
                        'message': f'Forbidden parameter detected: {param}'
                    })
    return issues

def check_pam_config(is_remote=False):
    """CHECK PAM CONFIG AGAINST RULES"""
    issues = []

    if is_remote:
        pam_files, sftp, ssh = remote.get_remote_file_list("192.168.1.2", "kali", '/etc/pam.d', "/etc/pam.conf", password='kali') # values should be inputs
    else:
        pam_files = []
        # Get PAM files
        pam_dir = '/etc/pam.d' # <----- CAN BE CHANGED
        pam_conf_file = '/etc/pam.conf'
        if os.path.isdir(pam_dir):
            for filename in os.listdir(pam_dir):
                pam_files.append(os.path.join(pam_dir, filename))
        if os.path.isfile(pam_conf_file):
            pam_files.append(pam_conf_file)


    for filepath in pam_files:
        if is_remote:
            is_pam_conf = (filepath == "/etc/pam.conf") # should be same as the input file above
            file = remote.get_remote_file(sftp, filepath)
            if file is None:
                print(f"Error reading remote file {filepath}")
            file_issues = get_pam_file_issues(file, is_pam_conf, filepath)
            if file_issues:
                for issue in file_issues:
                    issues.append(issue)
        
        
        else:
            is_pam_conf = (filepath == pam_conf_file)
            try:
                with open(filepath, 'r') as file:
                    file_issues = get_pam_file_issues(file, is_pam_conf, filepath)
                    if file_issues:
                        for issue in file_issues:
                            issues.append(issue)
                    
            except IOError as e:
                print(f"Error reading {filepath}: {e}")
    if is_remote:
        remote.close_ssh_con(ssh, sftp)
    if issues:
        #print("\n========= Password Configuration Issues Found =========\n")
        for issue in issues:
            report('password', issue['message'], issue['file'], issue['line'], issue['details'])
        #     print(f"""[red][ISSUE][/red] [#f01f23]{issue['message']}[/#f01f23]
        # [cyan]File:[/cyan]    [#990fbf]{os.path.dirname(issue['file'])}/[/#990fbf][#c31ff0]{os.path.basename(issue['file'])}[/#c31ff0]
        # [cyan]Line:[/cyan]    [#1fc6f0]{issue['line']}[/#1fc6f0]
        # [cyan]Details:[/cyan] [#f0ae1f]{issue['details']}[/#f0ae1f]\n\n""")
        #    print('Issue in: ', issue['file'], ' line: ', issue['line'], ' Issue message: ', issue['message'], 'issue: ', issue['issue_message'])
    else:
        print('No issues found.')