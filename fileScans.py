import os
import subprocess
import sys
from other import RemoteDeviceHandling
from other import setup_logger
from rich import print
import stat

# inputs:
# * if not remote: *
# pam directory path | default = /etc/pam.d
# pam config file path | default = /etc/pam.conf
#
# * if remote, the above plus: *
# ip address
# username
# password (if no keypath)
# key path (if no password)
#
# output:
# report function


# set up the logging handler:
logger = setup_logger()


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

SSH_RULES = [
    {
        'rule': 'PermitRootLogin Yes',
        'message': "PermitRootLogin should be 'no'.",
        'key': 'PermitRootLogin',
        'details': 'Prevents direct root access, reducing attack risk.'
    },
    {
        'rule': 'PasswordAuthentication yes',
        'message': "PasswordAuthentication should be 'no'. Use SSH keys instead.",
        'key': 'PasswordAuthentication',
        'details': 'Passwords are vulnerable to brute-force attacks; use SSH keys.'
    },
    {
        'rule': 'X11Forwarding yes',
        'message': "X11Forwarding should be 'no' to prevent remote GUI vulnerabilities.",
        'key': 'X11Forwarding',
        'details': 'Reduces exposure to X11-based remote exploits.'
    },
    {
        'rule': 'AllowTcpForwarding yes',
        'message': "AllowTcpForwarding should be 'no' to block unauthorized tunneling.",
        'key': 'AllowTcpForwarding',
        'details': 'Prevents SSH from being used for unauthorized tunneling.'
    },
    {
        'rule': 'MaxAuthTries < 3',
        'message': "MaxAuthTries should be set to 3 or lower.",
        'key': 'MaxAuthTries',
        'details': 'Limits brute-force attempts on SSH authentication.'
    }
]

# *********************************** OUTPUT ***********************************
def report(types, value1, value2, value3, value4):
    """ PRINTED OUTPUT """
    
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
# *******************************************************************************

class PAMConfScan:
    def __init__(self, is_remote=False, pam_dir='/etc/pam.d', pam_conf_file='/etc/pam.conf'):
        self.is_remote = is_remote
        
        self.issues = []
        self.pam_dir = pam_dir
        self.pam_conf_file = pam_conf_file

        # Establish a remote connection with the target
        if self.is_remote:
            try:
                self.remote_connection = RemoteDeviceHandling("192.168.1.6", "kali", remote_dir_path = [self.pam_dir], remote_file_path = [self.pam_conf_file, '/etc/passwd'], password='kali')
            except (ValueError, ConnectionError, TimeoutError, RuntimeError) as e:
                logger.error(str(e))
                print(e)
                return
        
        # Run the scan and check for any errors
        try:
            self.check_pam_config()
            if self.issues:
                for issue in self.issues:
                    report('password', issue['message'], issue['file'], issue['line'], issue['details'])
            else:
                print('No issues found.')
        except (FileNotFoundError, IOError, RuntimeError) as e:
            print(e)

    def parse_pam_line(self, line, is_pam_conf):
        """ PARSE A LINE FROM PAM CONFIG FILE AND RETURN IT AS A LIST"""

        parts = line.strip().split()
        if not parts or parts[0].startswith('#'):
            return None
        
        # Handle multiple items inside []
        merged_parts = []
        inside_brackets = None
        for part in parts:
            if part.startswith('['):
                inside_brackets = []
                if part.endswith(']'):
                    inside_brackets.append(part.strip('[]'))
                    merged_parts.append(inside_brackets)
                    inside_brackets = None
                else:
                    inside_brackets.append(part.strip('['))

            elif part.endswith(']'):
                inside_brackets.append(part.strip(']'))
                merged_parts.append(inside_brackets)
                inside_brackets = None
            elif part.startswith('#'):
                break
            elif inside_brackets is not None:
                inside_brackets.append(part)
            else:
                merged_parts.append(part)

        # handle malformed line with no closing bracket ']'   
        if inside_brackets is not None:
            return 'malformed'
        
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
        try:
            module_name = os.path.basename(module)
        except Exception:
            return 'malformed'
        
        return {
            'service': service,
            'type': type_,
            'control': control,
            'module': module_name,
            'args': args
        }

    def evaluate_params(self, rule, params, filepath, line_num):
        if not isinstance(rule, dict) or not isinstance(params, dict):
            self.issues.append({
                'file': filepath,
                'line': line_num,
                'details': f'Incorrect syntax: {line}',
                'message': f'Malformed PAM Line'
            })
            return

        # Check required params
        required = rule.get('required_params', {})
        for param, expected in required.items():
            if param not in params:
                self.issues.append({
                    'file': filepath,
                    'line': line_num,
                    'details': rule['message'],
                    'message': f'Missing required parameter: {param}'
                })
            elif expected is not None and params[param] != expected:
                self.issues.append({
                    'file': filepath,
                    'line': line_num,
                    'details': rule['message'],
                    'message': f'Incorrect value for {param}, expected: {expected}'
                })

        # Check forbidden params
        forbidden = rule.get('forbidden_params', [])
        for param in forbidden:
            if param in params:
                self.issues.append({
                    'file': filepath,
                    'line': line_num,
                    'details': rule['message'],
                    'message': f'Forbidden parameter detected: {param}'
                })

    def scan_pam_file_issues(self, file, is_pam_conf, filepath):
        """TAKES A FILE NAME, WHETHER IT'S THE PAM CONF FILE AND ITS PATH
            PARSES EACH LINE FROM THE PAM FILE AND THEN
            CHECKS FOR ANY PARAMETERS AND SENDS THEM TO evaluate_params
            TO COMPARE THEM AGAINST SECURITY RULES"""
        
        for line_num, line in enumerate(file, 1):
            parsed = self.parse_pam_line(line, is_pam_conf)
            if not parsed:
                continue
            elif parsed == 'malformed':
                #print(parsed)  
                self.issues.append({
                    'file': filepath,
                    'line': line_num,
                    'details': f'Incorrect syntax: {line}',
                    'message': f'Malformed PAM Line' 
                })
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
                self.evaluate_params(rule, params, filepath, line_num)

    def _get_pam_files(self):
        """GETS FILEPATHS OF PAM.D AND PAM.CONF FILES WHETHER IT IS REMOTELY OR LOCALLY"""
        if self.is_remote:
            # pam_files = get_remote_file_list("192.168.1.2", "kali", self.pam_dir, self.pam_conf_file, password='kali') # values should be inputs
            pam_files = self.remote_connection.get_remote_file_list()
                
        else:
            pam_files = []
            # Get PAM files
            if os.path.isdir(self.pam_dir):
                for filename in os.listdir(self.pam_dir):
                    pam_files.append(os.path.join(self.pam_dir, filename))
            if os.path.isfile(self.pam_conf_file):
                pam_files.append(self.pam_conf_file)
        return pam_files

    def check_pam_config(self):
        """USE THE PAM FILE LIST (FROM _get_pam_files()) TO GET A LIST OF FILEPATHS AND GET THEIR CONTENTS
            THEN SEND EACH FILE TO THE scan_pam_file_issues FUNCTION TO ADD EACH ISSUE
            TO THE ARRAY OF LISTS CALLED issues"""
        try:
            pam_files = self._get_pam_files()
        except Exception:
            logger.warning('Could not access pam files')
            return

        for filepath in pam_files:
            is_pam_conf = (filepath == self.pam_conf_file) # should be same as the input file above
            if self.is_remote:
                try:
                    file = self.remote_connection.get_remote_file(filepath)
                except Exception:
                    logger.warning(f'Could not access remote pam file: {filepath}')
                    continue

                self.scan_pam_file_issues(file, is_pam_conf, filepath)
           
            else:
                try:
                    with open(filepath, 'r') as file:
                        self.scan_pam_file_issues(file, is_pam_conf, filepath)                       
                except IOError as e:
                    print(f"Error reading {filepath}: {e}")
        if self.is_remote:
            try:
                self.remote_connection.close_ssh_con()
            except Exception:
                logger.warning('Could not close ssh connection to remote device')


# FIX THESE TO NOT CHECK COMMENT LINES and FIX SFTP CHECKS
class FileConfScan:
    def __init__(self, is_remote=False, ssh_config_file='/etc/ssh/sshd_config', apache_config_file='/etc/apache2/apache2.conf'):
        print("🔍 Scanning system configurations for security issues...\n") # CHANGE THIS <---------------------
        self.is_remote = is_remote
        self.ssh_issues = []
        self.apache_issues = []
        self.sftp_issues = []

        self.ssh_config_file = ssh_config_file
        self.apache_config_file = apache_config_file

        if self.is_remote:
            try:
                self.remote_connection = RemoteDeviceHandling("192.168.1.4", "kali", remote_dir_path = None, remote_file_path = [self.ssh_config_file], password='kali')
            except (ValueError, ConnectionError, TimeoutError, RuntimeError) as e:
                logger.error(str(e))
                print(e)
                return

        try:
            self.check_ssh_config()
            self.check_apache_config()
            self.check_sftp_config()
        except Exception as e:
            logger.error('Configuration scans failed: ', str(e))
            print('Failed to perform configuration scans')
            return

        # THEN OUTPUT ALL THE ISSUES
        if not self.ssh_issues and not self.apache_issues and not self.sftp_issues:
            print("✅ No insecure configurations found. System is secure!")
            return

        if self.ssh_issues:
            for issue in self.ssh_issues:
                report('misconfig', issue['message'], self.ssh_config_file, issue['key'], issue['details'])
        
        if self.apache_issues:
            print("\n🚨 Apache Misconfigurations Found:")
            for issue in self.apache_issues:
                print(f"  - {issue}")

        if self.sftp_issues:
            print("\n🚨 SFTP Misconfigurations Found:")
            for issue in self.sftp_issues:
                print(f"  - {issue}")
        
        if not self.is_remote:
            try:
                self.optional_fixing()
            except Exception as e:
                logger.error('Fixing misconfigurations failed: ', str(e))
                print('Failed to fix misconfigurations')
                return

        print("\n🔹 Scan Complete.")

    def check_ssh_config(self):
        if self.is_remote:
            lines = self.remote_connection.get_remote_file(self.ssh_config_file)
        else:
            with open(self.ssh_config_file, "r") as file: # <----------------- HANDLE ERRORS LIKE FILE NOT FOUND
                lines = file.readlines()
        
        for line in lines:
            for rule in SSH_RULES:
                if len(rule['rule'].split()) == 2:
                    if rule['rule'] in line:
                        self.ssh_issues.append({
                            'message': rule['message'],
                            'file': self.ssh_config_file,
                            'key': rule['key'],
                            'details': rule['details']
                        })
                elif len(rule['rule'].split()) == 3 and len(line.split()) > 1 and line.split()[-1].isdigit():
                    split_rule = rule['rule'].split()
                    if split_rule[1] == '<':
                        if split_rule[0] in line and int(line.split()[-1]) > int(split_rule[2]):
                            self.ssh_issues.append({
                            'message': rule['message'],
                            'file': self.ssh_config_file,
                            'key': rule['key'],
                            'details': rule['details']
                        })

    def check_apache_config(self):
        if self.is_remote:
            lines = self.remote_connection.get_remote_file(self.apache_config_file)
        else:
            with open(self.apache_config_file, "r") as file:
                lines = file.readlines()

        for line in lines:
            if "Options Indexes" in line:
                self.apache_issues.append("Remove 'Indexes' from 'Options' to prevent directory listing.")
            if "ServerTokens Full" in line:
                self.issues.append("ServerTokens should be 'Prod' to hide Apache version details.")
            if "ServerSignature On" in line:
                self.issues.append("ServerSignature should be 'Off' to remove Apache error page info.")

    def check_sftp_config(self):
        if self.is_remote:
            lines = self.remote_connection.get_remote_file(self.ssh_config_file)
        else:
            with open(self.ssh_config_file, "r") as file:
                lines = file.readlines()

        for line in lines:
            if "Subsystem sftp" in line and "internal-sftp" not in line:
                self.sftp_issues.append("SFTP should use 'internal-sftp' for security.")

    def optional_fixing(self):
        # Ask the user if they want to fix issues
        choice = input("\nWould you like to fix these issues automatically? (yes/no): ").strip().lower()

        if choice == "yes":
            if self.ssh_issues:
                self.fix_ssh_config()
            if self.apache_issues:
                self.fix_apache_config()
            if self.sftp_issues:
                self.fix_sftp_config()
        else:
            print("❌ No changes were made. Please review the issues manually.")

    def fix_ssh_config(self):
        print("\nApplying secure SSH configurations...")
        os.system("sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak")  # Backup
        os.system("sudo sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config")
        os.system("sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config")
        os.system("sudo sed -i 's/^X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config")
        os.system("sudo sed -i 's/^AllowTcpForwarding yes/AllowTcpForwarding no/' /etc/ssh/sshd_config")
        os.system("sudo sed -i 's/^MaxAuthTries [0-9]*/MaxAuthTries 3/' /etc/ssh/sshd_config")
        os.system("sudo systemctl restart ssh")
        print("✅ SSH configurations updated successfully!")

    def fix_apache_config(self):
        print("\nApplying secure Apache configurations...")
        os.system("sudo cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.bak")  # Backup
        os.system("sudo sed -i 's/Options Indexes/Options -Indexes/' /etc/apache2/apache2.conf")
        os.system("sudo sed -i 's/ServerTokens Full/ServerTokens Prod/' /etc/apache2/apache2.conf")
        os.system("sudo sed -i 's/ServerSignature On/ServerSignature Off/' /etc/apache2/apache2.conf")
        os.system("sudo systemctl restart apache2")
        print("✅ Apache configurations updated successfully!")

    def fix_sftp_config(self):
        print("\nApplying secure SFTP configurations...")
        os.system("sudo sed -i 's|^Subsystem sftp.*|Subsystem sftp internal-sftp|' /etc/ssh/sshd_config")
        os.system("sudo systemctl restart ssh")
        print("✅ SFTP configurations updated successfully!")


class PermissionScan:
    def __init__(self, shutdown_event, root_dir='/'):
        self.shutdown_event = shutdown_event
        self.root_dir = root_dir
        self.ww_files = [] # world writeable files
        self.incorrect_files = [] # files with incorrect permissions

        try:
            self.find_world_writable_files()
            self.find_sensitive_files_with_issues()
        except Exception as e:
            logger.error(str(e))
            print('Error while performing permission scans')
            return

        if self.ww_files:
            print("\nWorld-writable files found:")
            for f in self.ww_files:
                print(f)
        else:
            print("No world-writable files found.")

            print("\nScanning for sensitive files with incorrect permissions...")

        if self.incorrect_files:
            print("\nSensitive files with incorrect permissions:")
            for f, correct_mode in self.incorrect_files:
                current_mode = os.stat(f).st_mode & 0o777
                print(f"{f}: Current -> {oct(current_mode)}, Expected -> {oct(correct_mode)}")
        else:
            print("All sensitive files have correct permissions.")


    def is_world_writable(self, file_path):
        try:
            file_stat = os.stat(file_path)
            return bool(file_stat.st_mode & stat.S_IWOTH)  # Check world-writable bit
        except Exception as e:
            # print("Error in is_world_writeable: ", e)
            return False

    def has_incorrect_permissions(self, file_path, correct_mode):
        try:
            file_stat = os.stat(file_path)
            return (file_stat.st_mode & 0o777) != correct_mode  # Compare permissions
        except Exception as e:
            # print("Error in has_incorrect_permissions: ", e)
            return False
    
    def find_world_writable_files(self): # try to make it concurrent <-----
        for root, _, files in os.walk(self.root_dir):
            # handle shutdowns
            if self.shutdown_event.is_set():
                    break
                
            for file in files:
                # handle shutdowns
                if self.shutdown_event.is_set():
                    break

                file_path = os.path.join(root, file)
                if self.is_world_writable(file_path):
                    self.ww_files.append(file_path)

    def find_sensitive_files_with_issues(self):
        sensitive_files = {
            "/etc/passwd": 0o644,
            "/etc/shadow": 0o640,
            "/etc/group": 0o644,
            "/etc/gshadow": 0o640,
            os.path.expanduser("~/.ssh/id_rsa"): 0o600,
            os.path.expanduser("~/.ssh/id_rsa.pub"): 0o644,
        }

        for file, correct_mode in sensitive_files.items():
            if os.path.exists(file) and self.has_incorrect_permissions(file, correct_mode):
                self.incorrect_files.append((file, correct_mode))