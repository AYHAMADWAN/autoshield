import os
import stat

def is_world_writable(file_path):
    try:
        file_stat = os.stat(file_path)
        return bool(file_stat.st_mode & stat.S_IWOTH)  # Check world-writable bit
    except Exception as e:
        return False

def has_incorrect_permissions(file_path, correct_mode):
    try:
        file_stat = os.stat(file_path)
        return (file_stat.st_mode & 0o777) != correct_mode  # Compare permissions
    except Exception as e:
        return False

def find_world_writable_files(root_dir="/home/linux/"):
    world_writable_files = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            file_path = os.path.join(root, file)
            if is_world_writable(file_path):
                world_writable_files.append(file_path)
    return world_writable_files

def find_sensitive_files_with_issues():
    sensitive_files = {
        "/etc/passwd": 0o644,
        "/etc/shadow": 0o640,
        "/etc/group": 0o644,
        "/etc/gshadow": 0o640,
        os.path.expanduser("~/.ssh/id_rsa"): 0o600,
        os.path.expanduser("~/.ssh/id_rsa.pub"): 0o644,
    }
    
    incorrect_files = []
    for file, correct_mode in sensitive_files.items():
        if os.path.exists(file) and has_incorrect_permissions(file, correct_mode):
            incorrect_files.append((file, correct_mode))
    return incorrect_files

def fix_permissions(file_path, correct_mode):
    try:
        current_mode = os.stat(file_path).st_mode & 0o777
        print(f"Fixing permissions for {file_path}: {oct(current_mode)} -> {oct(correct_mode)}")
        os.chmod(file_path, correct_mode)
        print(f"Fixed permissions for {file_path}")
    except Exception as e:
        print(f"Failed to fix permissions for {file_path}: {e}")

def main():
    print("Scanning for world-writable files...")
    ww_files = find_world_writable_files()
    if ww_files:
        print("\nWorld-writable files found:")
        for f in ww_files:
            print(f)
    else:
        print("No world-writable files found.")
    
    print("\nScanning for sensitive files with incorrect permissions...")
    bad_sensitive_files = find_sensitive_files_with_issues()
    if bad_sensitive_files:
        print("\nSensitive files with incorrect permissions:")
        for f, correct_mode in bad_sensitive_files:
            current_mode = os.stat(f).st_mode & 0o777
            print(f"{f}: Current -> {oct(current_mode)}, Expected -> {oct(correct_mode)}")
            # fix_permissions(f, correct_mode)
    else:
        print("All sensitive files have correct permissions.")