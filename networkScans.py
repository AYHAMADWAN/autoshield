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
                    # print(f"Stopped at port: {port}")
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
                # print(f"Stopped at service port: {port}")
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
            raise RuntimeError(f"Error while checking service {e}")


class FirewallScan:
    def __init__(self, tool = None):
        if not tool:
            self.tool = self.detect_firewall()
        else:
            self.tool = tool 
        self.weak_rules = []

    def run_scan(self):
        if self.tool == "iptables":
            weak = self.check_iptables_rules()
            if weak:
                print("\n[!] Weak iptables rules detected:")
                for w in weak:
                    print(f"  - {w}")
            else:
                print("\n[+] No weak rules found in iptables.")
        elif self.tool == "ufw":
            weak = self.check_ufw_rules()
            if weak:
                print("\n[!] Weak ufw rules detected:")
                for w in weak:
                    print(f"  - {w}")
            else:
                print("\n[+] No weak rules found in ufw.")
    
        elif self.tool == "nftables":
            weak = self.check_nftables_rules()
            if weak:
                print("\n[!] Weak nftables rules detected:")
                for w in weak:
                    print(f"  - {w}")
            else:
                print("\n[+] No weak rules found in nftables.")
        else:
            pass # could not identify firewall tool

    def run_cmd(self, command):
        try:
            return subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            raise RuntimeError('Error while running command')

    def detect_firewall(self):
        tools = {
            "iptables": "iptables -L",
            "ufw": "ufw status",
            "nftables": "nft list ruleset"
        }
        for name, cmd in tools.items():
            output = self.run_cmd(cmd)
            if output:
                detected = name
                break
                
        if not detected:
            raise RuntimeError('Could not detect a firewall tool')
        return detected

    def check_iptables_rules(self):
        rules_output = self.run_cmd("iptables -L -n --line-numbers")
        weak_rules = []

        for line in rules_output.splitlines():
            line_lower = line.lower()

            if "accept" in line_lower and ("0.0.0.0/0" in line or "anywhere" in line_lower):
                # Skip safe rules
                if any(x in line_lower for x in [
                    "ctstate related,established",
                    "icmptype 3",
                    "icmptype 8",
                    "icmptype 11",
                    "icmptype 12",
                    "udp spt:67 dpt:68",
                    "udp dpt:5353",
                    "udp dpt:1900"
                ]):
                    continue

                weak_rules.append(f"❗ Rule allows traffic from anywhere: {line.strip()}")

            # Specific ports
            if "dpt:22" in line and ("0.0.0.0/0" in line or "anywhere" in line_lower):
                weak_rules.append(f"⚠️ SSH port open to the world: {line.strip()}")
            if "dpt:23" in line:
                weak_rules.append(f"⚠️ Telnet port (23) open — insecure protocol: {line.strip()}")
            if "dpt:3389" in line:
                weak_rules.append(f"⚠️ RDP port (3389) open — risky on public interfaces: {line.strip()}")
            if "dpt:21" in line:
                weak_rules.append(f"⚠️ FTP port (21) open — insecure file transfer: {line.strip()}")
            if "dpt:80" in line or "dpt:443" in line:
                weak_rules.append(f"🔎 HTTP/HTTPS port open: {line.strip()}")

            # Allow all ports
            if re.search(r'dpts?:\s*0:65535', line_lower):
                weak_rules.append(f"❗ All ports are open in this rule: {line.strip()}")

            # Accept without specifying protocol/source
            if re.search(r'ACCEPT\s+all\s+--', line):
                weak_rules.append(f"❗ Accepts all traffic (protocol/source not filtered): {line.strip()}")

        # Check for default policy
        default_policy_output = self.run_cmd("iptables -S")
        if "-P INPUT ACCEPT" in default_policy_output:
            weak_rules.append("⚠️ Default INPUT policy is ACCEPT — should be DROP")
        if "-P FORWARD ACCEPT" in default_policy_output:
            weak_rules.append("⚠️ Default FORWARD policy is ACCEPT — should be DROP or REJECT")

        return weak_rules

    def check_ufw_rules(self):
        rules_output = self.run_cmd("ufw status numbered")
        weak_rules = []

        print("\n[*] Analyzing UFW rules...\n")

        for line in rules_output.splitlines():
            line_lower = line.lower()

            if "allow" in line_lower:
                if "anywhere" in line_lower or "0.0.0.0/0" in line_lower:
                    weak_rules.append(f"❗ Rule allows traffic from anywhere: {line.strip()}")

                if "22" in line:
                    weak_rules.append(f"⚠️ SSH port (22) open to the world: {line.strip()}")
                if "23" in line:
                    weak_rules.append(f"⚠️ Telnet port (23) open — insecure protocol: {line.strip()}")
                if "3389" in line:
                    weak_rules.append(f"⚠️ RDP port (3389) open — risky on public interfaces: {line.strip()}")
                if "21" in line:
                    weak_rules.append(f"⚠️ FTP port (21) open — insecure file transfer: {line.strip()}")
                if "80" in line or "443" in line:
                    weak_rules.append(f"🔎 HTTP/HTTPS port open: {line.strip()}")

        return weak_rules

    def check_nftables_rules(self):
        rules_output = self.run_cmd("nft list ruleset")
        weak_rules = []
        seen_rules = set()

        print("\n[*] Analyzing nftables rules...\n")

        for line in rules_output.splitlines():
            line_lower = line.lower().strip()

            # Skip benign rules for localhost interface and related/established connections
            if re.search(r'(iifname\s+"lo"|oifname\s+"lo")', line_lower):
                continue
            if re.search(r'ct state related,established', line_lower):
                continue

            # Accept all from anywhere with no filters
            if re.search(r'accept\s*$', line_lower) and not re.search(r'dport|saddr|proto|ip|meta', line_lower):
                msg = f"❗ Blind ACCEPT rule with no filters: {line.strip()}"
                if msg not in seen_rules:
                    weak_rules.append(msg)
                    seen_rules.add(msg)

            # Accepts traffic from anywhere (saddr any or 0.0.0.0/0)
            if re.search(r'ip\s+saddr\s+(0\.0\.0\.0/0|any)', line_lower) and "accept" in line_lower:
                msg = f"❗ Accepts traffic from anywhere: {line.strip()}"
                if msg not in seen_rules:
                    weak_rules.append(msg)
                    seen_rules.add(msg)

            # Ports to check (SSH, Telnet, RDP, FTP, HTTP/HTTPS)
            ports = {
                22: "⚠️ SSH port open",
                23: "⚠️ Telnet port open — insecure protocol",
                3389: "⚠️ RDP port open — risky",
                21: "⚠️ FTP port open — insecure",
                80: "🔎 HTTP port open",
                443: "🔎 HTTPS port open"
            }

            for port, alert in ports.items():
                # Match tcp dport or udp dport (just in case)
                pattern = rf'(tcp|udp)?\s*dport\s+{port}'
                if re.search(pattern, line_lower):
                    msg = f"{alert}: {line.strip()}"
                    if msg not in seen_rules:
                        weak_rules.append(msg)
                        seen_rules.add(msg)

        if not rules_output.strip():
            weak_rules.append("⚠️ nftables appears to be installed but has no active ruleset.")

        return weak_rules


# obj = FirewallScan()
# obj.run_scan()