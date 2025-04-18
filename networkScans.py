import socket
import threading
import re
from other import setup_logger
from concurrent.futures import ThreadPoolExecutor
import stat
import subprocess
import os

# set up the logging handler:
logger = setup_logger()

class PortScan:
    def __init__(self, shutdown_event, target='127.0.0.1', start_port=1, end_port=65535, timeout=0.5):
        self.target = target
        self.timeout = timeout
        self.shutdown_event = shutdown_event
        self.port_range = range(start_port, end_port + 1)
        self.open_ports = []
        self.services = {}

        if not self.is_valid_ip():
            logger.error('The provided IP Address for remote port scanning is invalid')
            print("Invalid IP address.")
            return

        logger.info(f'Starting Port Scan on host {target} [port {start_port}-{end_port}]')
        print("Scanning for open ports...")

        self.scan_ports()

        if self.open_ports:
            print(f"Open ports: {self.open_ports}")
            
            print("Identifying services...")
            # handle shutdowns
            if self.shutdown_event.is_set():
                print(f"Could not perform service scan due to abrupt shutdown")
                return
            self.identify_services()
            for port, service in self.services.items():
                print(f"Port {port}: {service}")
        else:
            print("No open ports found.")

    def scan_ports(self):
        threads = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = []
            for port in self.port_range:
                if self.shutdown_event.is_set():
                    print(f"Stopped at port: {port}")
                    break
                futures.append(executor.submit(self.scan_port, port))
        
    def scan_port(self, port):
        if self.shutdown_event.is_set():
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)  # Configurable timeout for balancing speed and accuracy
            result = s.connect_ex((self.target, port))
            if result == 0:
                self.open_ports.append(port)
        except socket.timeout:
            logger.debug(f'Timeout while scanning port {port}')
        except socket.error as e:
            logger.debug(f'Socket error on port {port}: {e}')
        except Exception as e:
            logger.error(f'Unexpected socket error while scanning port {port}')
        finally:
            s.close()

    def is_valid_ip(self):
        pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        if pattern.match(self.target):
            return all(0 <= int(octet) <= 255 for octet in self.target.split("."))
        return False
    
    def identify_services(self):
        for port in self.open_ports:
            # handle shutdowns
            if self.shutdown_event.is_set():
                    print(f"Stopped at service port: {port}")
                    break
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "Unknown"
            self.services[port] = service  

class FirewallScan:
    def __init__(self):
        self.firewall_rules_scan() #temporary, should be changed later
        
    def firewall_rules_scan(self):
        # This function checks what firewall service is available
        # and prints the list of firewall rules present
        # ** need a function to process these rules to check
        #    which rules are bad.

        print("\nScanning firewall rules...")

        # Try UFW
        try:
            result = subprocess.run(['ufw', 'status'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if "inactive" in result.stdout.lower():
                print("UFW is installed but inactive.")
            else:
                print("UFW firewall rules:")
                print(result.stdout)
            return
        except FileNotFoundError:
            pass # raise/handle error + more errors

        # Try firewalld
        try:
            result = subprocess.run(['firewall-cmd', '--list-all'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                print("Firewalld rules:")
                print(result.stdout)
                return
        except FileNotFoundError:
            pass # raise/handle error + more errors

        # Try iptables
        try:
            result = subprocess.run(['iptables', '-L'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print("iptables rules:")
            print(result.stdout)
        except FileNotFoundError: # raise/handle error + more errors
            print("No supported firewall tools found (ufw, firewalld, iptables).")





# Plan For Port Service Mappings:
#     Use socket.getservbyport(port) to check the common service
#     associated with that port and then use systemctl? to check
#     if that service is actually running