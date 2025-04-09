import os
import sys
import argparse
from fileScans import PAMConfScan, FileConfScan, PermissionScan
from networkScans import PortScan
# import ports
from rich import print
import time
import signal
from concurrent.futures import ThreadPoolExecutor
import threading

# Exit before errors occur
# privileges
# note: handle keyboard interrupts error ✅
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

shutdown_event = threading.Event()
def handle_signal(signum, frame):
    print("\n[!] Signal received. Shutting down gracefully...")
    shutdown_event.set()

signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)


def pass_scan():
    # passwords.check_pam_config()
    PAMConfScan()

def config_scan():
    # configs.main() # FIX THIS TO CHECK IF THE CONFIG FILES EXIST
    FileConfScan()

def perm_scan():
    PermissionScan(shutdown_event, root_dir='/')

def port_scan():
    # ports.main(shutdown_event)
    PortScan(shutdown_event)#, target='192.168.1.9')

def remote_scan():
    PAMConfScan(True)
    FileConfScan(True)

with ThreadPoolExecutor(max_workers=10) as executor:
    if args.permission:
        print('🔍 Scanning permissions of files...\n')
        # perm_scan()
        executor.submit(perm_scan)

    if args.passwords:
        print('🔍 Scanning password files for security issues...\n')
        # pass_scan()
        executor.submit(pass_scan)

    if args.config:
        #print('=' * 80)
        # config_scan()
        config_scan()

    if args.port:
        # print('=' * 80)
        print('🔍 Scanning ports for security issues...\n')
        port_scan()

    if args.remote:
        # print('=' * 80)
        print('🔍 Scanning remote host password and config files for security issues...\n')
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