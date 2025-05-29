import os
import pwd
from time import sleep
import threading
import psutil

SCORES = {
    "internet_connection": 5,
    "local_socket": 1,
    "suspicious_dir_usage": 3,
    "ld_preload": 4,
    "writable_executable_map": 4,
    "untrusted_exe": 2,
    "hidden_executable": 2,
    "suspicious_directory": 3,
    "suspicious_sys_user": 4,
    "suspicious_user": 2,
    "deleted_or_unreadable_exe": 5,
    "high_cpu_usage": 4
}

process_scores = {}

def add_suspicion(pid, reason, score, exe):
    if pid not in process_scores:
        process_scores[pid] = {"exe":exe, "score":0, "reasons":[]}
    process_scores[pid]['score'] += score
    process_scores[pid]['reasons'].append(reason)

all_pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
trusted_uids = [1000]

def get_process_info(pid):
    try:
        try:
            exe_path = os.readlink(f'/proc/{pid}/exe')
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            exe = '[unreadable exe]'
        cmdline = open(f'/proc/{pid}/cmdline', 'r').read().replace('\x00', ' ').strip()
        uid = int(os.stat(f'/proc/{pid}').st_uid)
        user = pwd.getpwuid(uid).pw_name
        return {
            'pid': pid,
            'exe': exe_path,
            'cmdline': cmdline,
            'user': {
                'username' : user,
                'uid': uid
            }
        }
    except Exception as e:
        # print(f'[WARN] Skipped PID {pid}: {e}')
        return None

def is_hidden(exe_path):
    try:
        # Check if the binary itself is hidden
        if os.path.basename(exe_path).startswith('.'):
            return True
        # Check if any parent directory is hidden
        parts = exe_path.strip('/').split('/')
        return any(part.startswith('.') for part in parts)
    except Exception as e:
        print(f'[ERR] Hidden check failed: {e}')
        return False

def is_suspicious_directory(pid, exe_path):
    suspicious_paths = [
        '/tmp',
        '/var/tmp',
        '/dev/shm',
        '/run',
        '/home',
        '/root'
    ]
    try:
        for path in suspicious_paths:
            if exe_path.startswith(path):
                add_suspicion(pid, 'Running from a suspicious directory', SCORES['suspicious_directory'], exe_path)
        if is_hidden(exe_path):
            add_suspicion(pid, 'Running from a hidden directory or file', SCORES['hidden_executable'], exe_path)
    except Exception as e:
        print(f'[ERR] Suspicious dir check failed: {e}')
        return False

def is_suspicious_user(pid, user, exe_path, uid):
    if user in ['nobody', 'daemon', 'sync', 'halt'] and not exe_path.startswith(("/usr", "/bin", "/sbin", "/lib")):
        add_suspicion(pid, 'System user is running a process from an unusual direcyory', SCORES['suspicious_sys_user'], exe_path)

    if user == "root" and not exe_path.startswith(("/usr", "/bin", "/sbin", "/init")):
       add_suspicion(pid, 'Root user is running a process from an unusual direcyory', SCORES['suspicious_sys_user'], exe_path)

    elif uid > 999 and uid not in trusted_uids:
        add_suspicion(pid, 'Process is running by an untrusted user', SCORES['suspicious_user'], exe_path)
    
    user_home = os.path.expanduser(f"~{user}")
    if exe_path.startswith("/home") and not exe_path.startswith(user_home):
        add_suspicion(pid, "User is running a process from another user's home directory", SCORES['suspicious_directory'], exe_path)

def get_socket_inodes():
    inodes = []
    files = ['/proc/net/tcp', '/proc/net/udp']

    for file in files:
        try:
            with open(file, 'r') as f:
                lines = f.readlines()[1:] # skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 10:
                        if parts[9] not in inodes:
                            inodes.append(parts[9])
        except Exception as e:
            print(e)
            continue
    return inodes

# add more and check for more
trusted_network_exe = ("/usr/sbin/sshd", "/usr/bin/ssh", "/usr/bin/nginx", "/usr/sbin/apache2", "/init", "/usr/lib/systemd", "/usr/bin/udevadm", "/usr/bin/dbus-daemon", "/usr/sbin/rsyslogd", "/usr/bin/login", "/usr/bin/sudo", "/usr/bin/python3.12", "/usr/sbin/cron")
trusted_file_exe = ("/usr/lib/systemd", "/usr/bin/login", "/usr/bin/python3.12", "/usr/sbin/cron")
# trusted_network_exe = ()
# trusted_file_exe = ()

suspicious_write_dirs = ["/tmp", "/dev/shm", "/run"]
inodes = get_socket_inodes()

def is_suspicious_behavior(pid, info):
    exe = info['exe']
    user = info['user']['username']
    result = []

    try:
        # check file descriptors for network connections or using suspicious files
        fd_dir = f"/proc/{pid}/fd"
        if os.path.exists(fd_dir):
            for fd in os.listdir(fd_dir):
                try:
                    target = os.readlink(os.path.join(fd_dir, fd))
                    if 'socket:' in target:
                        if not exe.startswith(trusted_network_exe):
                            inode = target[8:-1] # get the inode number
                            if inode in inodes and 'NET' not in result:
                                result.append('NET')
                            elif 'BHS' and 'BHS' not in result:
                                result.append('BHS')
                    if any(target.startswith(p) for p in suspicious_write_dirs):
                        if not exe.startswith(trusted_file_exe) and 'BHD' not in result:
                            result.append('BHD')
                except:
                    continue
        if 'NET' in result:
            add_suspicion(pid, 'Process is establishing an Internet connection (might be normal)', SCORES['internet_connection'], exe)
        if 'BHS' in result:
            add_suspicion(pid, 'Process is opening an internal socket (not connected to the internet)', SCORES['local_socket'], exe)
        if 'BHD' in result:
            add_suspicion(pid, 'Process is using a suspicious directory in its operations', SCORES['suspicious_dir_usage'], exe)

        # check the process's environment variables
        # read in binary mode since values are null \x00 separated rather than newline separated
        with open(f"/proc/{pid}/environ", "rb") as f:
            env = f.read().decode("utf-8", errors="ignore")
            # these vars are used to load shared libraries, useful for debugging but often used to inject malware
            if "LD_PRELOAD" in env or "LD_LIBRARY_PATH" in env: 
                add_suspicion(pid, 'Process is using suspicious environment variables that affect shared libraries loading', SCORES['ld_preload'], exe)

    except Exception as e:
        # print(f"[WARN] Behavior check failed for PID {pid}: {e}")
        pass
    return False

def has_suspicious_memory_maps(pid, info):
    exe = info['exe']
    try:
        with open(f'/proc/{pid}/maps', 'r') as f:
            for line in f:
                if 'rwxp' in line: # read-write-executable (not usually used by normal apps)
                    add_suspicion(pid, 'Process is using an executable with read, write and execute permissions in its memory', SCORES['writable_executable_map'], exe)
                if '[heap]' in line and 'x' in line.split()[1]: # executable in heap (not used by normal apps)
                    add_suspicion(pid, 'Process is using executables in heap', SCORES['writable_executable_map'], exe)
                if '[anon]' in line and 'x' in line.split()[1]: # executable not backed by a file (usually indicates shellcode loaders or malware)
                    add_suspicion(pid, 'Process is using a hidden executable in memory', SCORES['writable_executable_map'], exe)
    except Exception as e:
        # print(f'[WARN] Memory map check failed for PID {pid}: {e}')
        pass
    return False

def get_cpu_usage(pid):
    # this function does not calculate the current cpu usage of the process
    # is shows the process's cpu usage since it started
    try:
        with open(f"/proc/{pid}/stat", 'r') as f:
            values = f.read().split()
            utime = int(values[13]) # user mode jiffies
            stime = int(values[14]) # kernel mode jiffies
            starttime = int(values[21]) # process start time in jiffies

        with open('/proc/uptime', 'r') as f:
            uptime = float(f.read().split()[0])
        
        clk_tck = os.sysconf(os.sysconf_names['SC_CLK_TCK']) # get clock ticks per second (clock ticks are the same as jiffies)

        total_time = (utime + stime) / clk_tck # total time of the process using the CPU in seconds
        seconds_alive = uptime - (starttime / clk_tck) # how long the process has been running

        # calculate the cpu usage of the process since it started
        cpu_usage = 100 * (total_time / seconds_alive) if seconds_alive > 0 else 0

        return cpu_usage
    except Exception as e:
        # print(f"[WARN] CPU usage check failed for PID {pid} : {e}")
        return 0


def start_dynamic_scan(shutdown_event):
    try:
        with open('trusted_exe.txt', 'r') as file:
            trusted = [line.strip() for line in file]
    except Exception as e:
        trusted = []
    try: 
        # raise RuntimeError('ERROR: TEST')
        global process_scores
        suspicious = []

        for pid in all_pids:
            info = get_process_info(pid)
            if not info:
                continue
            exe = info['exe']
            user = info['user']['username']
            uid = info['user']['uid']

            if exe in trusted:
                continue

            is_suspicious_directory(pid, exe)
            is_suspicious_user(pid, user, exe, uid)
            is_suspicious_behavior(pid, info)
            has_suspicious_memory_maps(pid, info)
            # add_suspicion(pid, 'TEST', SCORES['high_cpu_usage'], exe)
            cpu = get_cpu_usage(pid)
            if cpu > 70 and user != "root":
                add_suspicion(pid, 'Suspiciously high cpu usage by a process', SCORES['high_cpu_usage'], exe)

            if '(deleted)' in exe or '[unreadable exe]' in exe:
                add_suspicion(pid, 'The process is running a deleted or unreadable executable file', SCORES["deleted_or_unreadable_exe"], exe)
            
            for pid, data in sorted(process_scores.items(), key=lambda x: x[1]["score"], reverse=True):
                if not data or not pid:
                    continue
                # print(f"⚠️ PID {pid} | {data['exe']} | Score: {data['score']}")
                # for reason in data["reasons"]:
                suspicious.append({
                    'PID': pid,
                    'Executable': data['exe'],
                    'Score': data['score'],
                    'Reasons': " || ".join(data['reasons'])
                })
                    # print(f"  └─ {reason}")
            
            process_scores = {}
            if shutdown_event.is_set():
                break

            # insert logic to delete previous output and get new output on gui <---------------------
        suspicious.append({'main': 'Executable'})
        return {'Process Scan Output:': suspicious}
    except Exception as e:
        return {'Process Scan Output:': [{'error': e},{'main':'error'}]}

def add_to_trusted(exe):
    try:
        with open('trusted_exe.txt', 'a+') as file:
            file.seek(0, os.SEEK_END)  # Move to the end of the file
            if file.tell() > 0:  # If file is not empty
                file.seek(file.tell() - 1)
                last_char = file.read(1)
                if last_char != '\n':
                    file.write('\n')
            file.write(exe + '\n')
    except FileNotFoundError:
        pass
    except Exception as e:
        return