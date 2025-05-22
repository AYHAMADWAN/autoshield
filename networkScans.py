import socket
import threading
import re
from other import setup_logger
from concurrent.futures import ThreadPoolExecutor
import stat
import subprocess
import os
from other import RemoteDeviceHandling


trusted = {22: 'sshd'}
# set up the logging handler:
logger = setup_logger()

class PortScan:
    def __init__(self, shutdown_event, target='127.0.0.1', start_port=1, end_port=65535, user = None, password = None, key_path = None, timeout=5):
        self.target = target
        self.user = user
        self.password = password
        self.key_path = key_path
        self.timeout = timeout
        self.shutdown_event = shutdown_event
        self.port_range = range(start_port, end_port + 1)
        self.open_ports = []
        self.suspicious_services = []
        
    def run_scan(self):
        if not self.is_valid_ip():
            logger.error('The provided IP Address for remote port scanning is invalid')
            return {'Port Scan Output:': [{'error': 'Invalid IP Address'}, {'main': 'error'}]}

        logger.info(f'Starting Port Scan on host {self.target}')

        try:
            # raise RuntimeError("ERROR: TEST")
            self.scan_ports()

            self.identify_services()

            if self.suspicious_services:
                self.suspicious_services.append({'main': 'port'})
                return {'Port Scan Output:': self.suspicious_services}
            else:
                return {'Port Scan Output:': [{'main': 'No issues found.'}]}
        except Exception as e:
            return {'Port Scan Output:': [{'error': e}, {'main': 'error'}]}

    def scan_ports(self):
        threads = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = []
            for port in self.port_range:
                if self.shutdown_event.is_set():
                    print(f"Stopped at port: {port}")
                    break
                futures.append(executor.submit(self.scan_port, port))
            
            for future in futures:
                try:
                    future.result()
                except Exception as e:
                    self.shutdown_event.set()
                    raise RuntimeError(f"Port scan aborted: {e}")
                    break
        
    def scan_port(self, port):
        if self.shutdown_event.is_set():
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((self.target, port))
            self.open_ports.append(port)
            # print(f"Port open {port}")
        except socket.timeout:
            raise RuntimeError("Socket Timeout")
            pass
        except socket.error as e:
            if e.errno == 113:
                raise RuntimeError("Destination Unreachable")
            elif e.errno == 101:
                raise RuntimeError("Network Unreachable")
            else:
                # raise RuntimeError(f"Error Scanning Ports{e}")
                pass
        except Exception as e:
            raise RuntimeError(e)
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
            # print(port)
            self.check_service(service, port)
            
    def check_service(self, expected_service, port):
        try:
            if self.target == '127.0.0.1':
                result = subprocess.run(['sudo', 'lsof', '-i', f':{port}'], capture_output=True, text=True)
                output = result.stdout
            else:
                remote_device = RemoteDeviceHandling(self.target, self.user, remote_dir_path = [], remote_file_path = [], password = self.password, key_path = self.key_path)
                ssh_con = remote_device.get_con()
                stdin, stdout, stderr = ssh_con.exec_command(f"sudo -S lsof -i:{port}")
                stdin.write(f"{self.password}\n")  # send sudo password
                stdin.flush()
                output = stdout.read().decode()
                
            lines = output.strip().split('\n')

            if len(lines) <= 1:
                self.suspicious_services.append({
                    'port': 'port:' + str(port),
                    'expected_service': expected_service,
                    'actual_service': 'Unknown',
                    'reason': 'Cannot identify the actual service running on that port'})
                return
            actual_service = lines[1].split()[0]
            
            if expected_service == "Unknown":
                self.suspicious_services.append({
                    'port': 'port:' + str(port),
                    'expected_service': expected_service,
                    'actual_service': actual_service,
                    'reason': f'Undefined expected service on this port, actual service is {actual_service}'})
                return
            if port in trusted and actual_service == trusted[port]:
                return
            if expected_service in result.stdout:
                return

            self.suspicious_services.append({
                'port': 'port:' + str(port),
                'expected_service': expected_service,
                'actual_service': actual_service,
                'reason': 'The service running on this port is not the expected service and is not a trusted process'})
        except Exception as e:
            print('error', e)
        



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