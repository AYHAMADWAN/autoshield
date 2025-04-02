import os
import sys
import argparse
import passwords
import configs
import perms
import ports
from rich import print

# Exit before errors occur
# privileges
# note: handle keyboard interrupts error
if os.getuid() != 0:
    print("Need elevated privileges")
    sys.exit(1)

# CLI
parser = argparse.ArgumentParser(prog='autoshield', usage=None, description='***DESCRIPTION***', epilog='***EPILOGE***')
parser.add_argument('-p', '--passwords', help='desc', action='store_true')
parser.add_argument('-c', '--config', help='desc', action='store_true')
parser.add_argument('-m', '--permission', help='desc', action='store_true')
parser.add_argument('-o', '--port', help='desc', action='store_true')
parser.add_argument('-a', '--all', help='desc', action='store_true')
parser.add_argument('-r', '--remote', help='desc', action='store_true')
args = parser.parse_args()

#print(vars(args))




def pass_scan():
    passwords.check_pam_config()

def config_scan():
    configs.main() # FIX THIS TO CHECK IF THE CONFIG FILES EXIST

def perm_scan():
    perms.main()

def port_scan():
    ports.main()

def remote_scan():
    passwords.check_pam_config(True)

if args.passwords:
    print('🔍 Scanning password files for security issues...\n')
    pass_scan()

if args.config:
    #print('=' * 80)
    config_scan()

if args.permission:
    print('=' * 80)
    perm_scan()

if args.port:
    print('=' * 80)
    port_scan()

if args.remote:
    print('=' * 80)
    remote_scan()

if args.all:
    print('🔍 Scanning password files for security issues...\n')
    pass_scan()

    #print('=' * 80)
    config_scan()

    print('=' * 80)
    perm_scan()

    print('=' * 80)
    port_scan()