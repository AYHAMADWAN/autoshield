import os
import subprocess
import passwords as ps

ssh_config_file = "/etc/ssh/sshd_config"

SSH_RULES = [
    {
        'rule': 'PermitRootLogin Yes',
        'message': "PermitRootLogin should be 'no'.",
        'file': ssh_config_file,
        'key': 'PermitRootLogin',
        'details': 'Prevents direct root access, reducing attack risk.'
    },
    {
        'rule': 'PasswordAuthentication yes',
        'message': "PasswordAuthentication should be 'no'. Use SSH keys instead.",
        'file': ssh_config_file,
        'key': 'PasswordAuthentication',
        'details': 'Passwords are vulnerable to brute-force attacks; use SSH keys.'
    },
    {
        'rule': 'X11Forwarding yes',
        'message': "X11Forwarding should be 'no' to prevent remote GUI vulnerabilities.",
        'file': ssh_config_file,
        'key': 'X11Forwarding',
        'details': 'Reduces exposure to X11-based remote exploits.'
    },
    {
        'rule': 'AllowTcpForwarding yes',
        'message': "AllowTcpForwarding should be 'no' to block unauthorized tunneling.",
        'file': ssh_config_file,
        'key': 'AllowTcpForwarding',
        'details': 'Prevents SSH from being used for unauthorized tunneling.'
    },
    {
        'rule': 'MaxAuthTries < 3',
        'message': "MaxAuthTries should be set to 3 or lower.",
        'file': ssh_config_file,
        'key': 'MaxAuthTries',
        'details': 'Limits brute-force attempts on SSH authentication.'
    }
]


# Function to check SSH configurations
def check_ssh_config():
    issues = []
    ssh_config_file = "/etc/ssh/sshd_config"

    with open(ssh_config_file, "r") as file: # <----------------- HANDLE ERRORS LIKE FILE NOT FOUND
        lines = file.readlines()
    
    for line in lines:
        for rule in SSH_RULES:
            if len(rule['rule'].split()) == 2:
                if rule['rule'] in line:
                    issues.append({
                        'message': rule['message'],
                        'file': rule['file'],
                        'key': rule['key'],
                        'details': rule['details']
                    })
            elif len(rule['rule'].split()) == 3 and len(line.split()) > 1 and line.split()[-1].isdigit():
                split_rule = rule['rule'].split()
                if split_rule[1] == '<':
                    if split_rule[0] in line and int(line.split()[-1]) > int(split_rule[2]):
                        issues.append({
                        'message': rule['message'],
                        'file': rule['file'],
                        'key': rule['key'],
                        'details': rule['details']
                    })
    return issues

# Function to fix SSH configurations
def fix_ssh_config():
    print("\nApplying secure SSH configurations...")
    os.system("sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak")  # Backup
    os.system("sudo sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config")
    os.system("sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config")
    os.system("sudo sed -i 's/^X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config")
    os.system("sudo sed -i 's/^AllowTcpForwarding yes/AllowTcpForwarding no/' /etc/ssh/sshd_config")
    os.system("sudo sed -i 's/^MaxAuthTries [0-9]*/MaxAuthTries 3/' /etc/ssh/sshd_config")
    os.system("sudo systemctl restart ssh")
    print("✅ SSH configurations updated successfully!")

# Function to check Apache configurations
def check_apache_config():
    issues = []
    apache_config_file = "/etc/apache2/apache2.conf"

    with open(apache_config_file, "r") as file:
        lines = file.readlines()

    for line in lines:
        if "Options Indexes" in line:
            issues.append("Remove 'Indexes' from 'Options' to prevent directory listing.")
        if "ServerTokens Full" in line:
            issues.append("ServerTokens should be 'Prod' to hide Apache version details.")
        if "ServerSignature On" in line:
            issues.append("ServerSignature should be 'Off' to remove Apache error page info.")

    return issues

# Function to fix Apache configurations
def fix_apache_config():
    print("\nApplying secure Apache configurations...")
    os.system("sudo cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.bak")  # Backup
    os.system("sudo sed -i 's/Options Indexes/Options -Indexes/' /etc/apache2/apache2.conf")
    os.system("sudo sed -i 's/ServerTokens Full/ServerTokens Prod/' /etc/apache2/apache2.conf")
    os.system("sudo sed -i 's/ServerSignature On/ServerSignature Off/' /etc/apache2/apache2.conf")
    os.system("sudo systemctl restart apache2")
    print("✅ Apache configurations updated successfully!")

# Function to check SFTP configurations
def check_sftp_config():
    issues = []
    ssh_config_file = "/etc/ssh/sshd_config"

    with open(ssh_config_file, "r") as file:
        lines = file.readlines()

    for line in lines:
        if "Subsystem sftp" in line and "internal-sftp" not in line:
            issues.append("SFTP should use 'internal-sftp' for security.")

    return issues

# Function to fix SFTP configurations
def fix_sftp_config():
    print("\nApplying secure SFTP configurations...")
    os.system("sudo sed -i 's|^Subsystem sftp.*|Subsystem sftp internal-sftp|' /etc/ssh/sshd_config")
    os.system("sudo systemctl restart ssh")
    print("✅ SFTP configurations updated successfully!")

# Main function
def main():
    print("🔍 Scanning system configurations for security issues...\n")

    ssh_issues = check_ssh_config()
    apache_issues = check_apache_config()
    sftp_issues = check_sftp_config()

    if not ssh_issues and not apache_issues and not sftp_issues:
        print("✅ No insecure configurations found. System is secure!")
        return

    # Display found issues
    if ssh_issues:
        # print("\n🚨 SSH Misconfigurations Found:")
        # for issue in ssh_issues:
        #     print(f"  - {issue}")
        for issue in ssh_issues:
            ps.report('misconfig', issue['message'], issue['file'], issue['key'], issue['details'])

    if apache_issues:
        print("\n🚨 Apache Misconfigurations Found:")
        for issue in apache_issues:
            print(f"  - {issue}")

    if sftp_issues:
        print("\n🚨 SFTP Misconfigurations Found:")
        for issue in sftp_issues:
            print(f"  - {issue}")

    # Ask the user if they want to fix issues
    choice = input("\nWould you like to fix these issues automatically? (yes/no): ").strip().lower()

    if choice == "yes":
        if ssh_issues:
            fix_ssh_config()
        if apache_issues:
            fix_apache_config()
        if sftp_issues:
            fix_sftp_config()
    else:
        print("❌ No changes were made. Please review the issues manually.")

    print("\n🔹 Scan Complete.")

# if _name_ == "_main_":
#     if os.geteuid() != 0:
#         print("❌ This script must be run as root. Use: sudo python3 config_checker.py")
#     else:
#         main()