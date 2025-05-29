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
            # try:
            self.check_service(service, port)
            # except Exception as e:
                # raise RuntimeError(e)
            
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
            if expected_service in output:
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
        try:
            # raise RuntimeError('ERROR: TEST')
            if self.tool == "iptables":
                self.check_iptables_rules()
            elif self.tool == "ufw":
                self.check_ufw_rules()
            elif self.tool == "nftables":
                self.check_nftables_rules()
            else:
                return {"Firewall Scan Output:": [{'error': f'Could not identify tool {self.tool}'}, {'main': 'error'}]}
            # self.weak_rules = []
            if self.weak_rules:
                self.weak_rules.append({'main': 'rule type'})
                return {"Firewall Scan Output:": self.weak_rules}
            else:
                return {"Firewall Scan Output:": [{'main': 'No issues found.'}]}
        except Exception as e:
            return {"Firewall Scan Output:": [{'error': e}, {'main': 'error'}]}

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

        for line in rules_output.splitlines():
            line_lower = line.lower()

            # Try to extract the rule line number (first token)
            tokens = line.strip().split()
            rule_line = tokens[0] if tokens and tokens[0].isdigit() else None

            if "accept" in line_lower and ("0.0.0.0/0" in line or "anywhere" in line_lower):
                if any(x in line_lower for x in [
                    "ctstate related,established", "icmptype 3", "icmptype 8",
                    "icmptype 11", "icmptype 12", "udp spt:67 dpt:68",
                    "udp dpt:5353", "udp dpt:1900"
                ]):
                    continue
                self.weak_rules.append({
                    "rule type": "Accept from anywhere",
                    "description": "Rule allows traffic from any source",
                    "recommendation": "Restrict source IPs or remove the rule",
                    "rule line": rule_line,
                    "raw rule": line.strip()
                })

            if "dpt:22" in line and ("0.0.0.0/0" in line or "anywhere" in line_lower):
                self.weak_rules.append({
                    "rule type": "SSH open",
                    "description": "SSH port open to the world",
                    "recommendation": "Limit SSH access to specific IPs",
                    "rule line": rule_line,
                    "raw rule": line.strip()
                })

            if "dpt:23" in line:
                self.weak_rules.append({
                    "rule type": "Telnet open",
                    "description": "Telnet (port 23) open — insecure protocol",
                    "recommendation": "Disable Telnet, use SSH instead",
                    "rule line": rule_line,
                    "raw rule": line.strip()
                })

            if "dpt:3389" in line:
                self.weak_rules.append({
                    "rule type": "RDP open",
                    "description": "RDP (port 3389) open — risky on public interfaces",
                    "recommendation": "Restrict or tunnel RDP through VPN",
                    "rule line": rule_line,
                    "raw rule": line.strip()
                })

            if "dpt:21" in line:
                self.weak_rules.append({
                    "rule type": "FTP open",
                    "description": "FTP (port 21) open — insecure file transfer",
                    "recommendation": "Use SFTP or FTPS instead",
                    "rule line": rule_line,
                    "raw rule": line.strip()
                })

            if "dpt:80" in line or "dpt:443" in line:
                self.weak_rules.append({
                    "rule type": "Web ports open",
                    "description": "HTTP/HTTPS ports are open",
                    "recommendation": "Ensure services are properly secured",
                    "rule line": rule_line,
                    "raw rule": line.strip()
                })

            if re.search(r'dpts?:\s*0:65535', line_lower):
                self.weak_rules.append({
                    "rule type": "All ports open",
                    "description": "All ports are open in this rule",
                    "recommendation": "Close unused ports; define specific services",
                    "rule line": rule_line,
                    "raw rule": line.strip()
                })

            if re.search(r'ACCEPT\s+all\s+--', line):
                self.weak_rules.append({
                    "rule type": "Accept all",
                    "description": "Accepts all traffic (protocol/source not filtered)",
                    "recommendation": "Add filtering rules or drop by default",
                    "rule line": rule_line,
                    "raw rule": line.strip()
                })

    def check_ufw_rules(self):
        rules_output = self.run_cmd("ufw status numbered")

        for line in rules_output.splitlines():
            line_lower = line.lower()
            # print(line)

            # Extract rule number from line like: "[ 1] 22                         ALLOW IN    Anywhere"
            rule_line_match = re.search(r'\[\s*(\d+)\s*\]', line)
            rule_line = rule_line_match.group(1) if rule_line_match else None

            if "allow" in line_lower:
                if "anywhere" in line_lower or "0.0.0.0/0" in line_lower:
                    self.weak_rules.append({
                        "rule type": "Allow from anywhere",
                        "description": "Allows traffic from any source",
                        "recommendation": "Restrict allowed IPs or limit access scope",
                        "rule line": rule_line,
                        "raw rule": line.strip()
                    })

                if "22" in line:
                    self.weak_rules.append({
                        "rule type": "SSH open",
                        "description": "SSH port (22) open to the world",
                        "recommendation": "Limit SSH access to trusted IPs",
                        "rule line": rule_line,
                        "raw rule": line.strip()
                    })

                if "23" in line:
                    self.weak_rules.append({
                        "rule type": "Telnet open",
                        "description": "Telnet port (23) open — insecure protocol",
                        "recommendation": "Disable Telnet or replace with SSH",
                        "rule line": rule_line,
                        "raw rule": line.strip()
                    })

                if "3389" in line:
                    self.weak_rules.append({
                        "rule type": "RDP open",
                        "description": "RDP port (3389) open — public access",
                        "recommendation": "Restrict RDP or tunnel through VPN",
                        "rule line": rule_line,
                        "raw rule": line.strip()
                    })

                if "21" in line:
                    self.weak_rules.append({
                        "rule type": "FTP open",
                        "description": "FTP port (21) open — insecure file transfer",
                        "recommendation": "Use SFTP or FTPS instead of FTP",
                        "rule line": rule_line,
                        "raw rule": line.strip()
                    })

                if "80" in line or "443" in line:
                    self.weak_rules.append({
                        "rule type": "Web open",
                        "description": "HTTP/HTTPS ports (80/443) are open",
                        "recommendation": "Ensure web services are secured and necessary",
                        "rule line": rule_line,
                        "raw rule": line.strip()
                    })

    def check_nftables_rules(self):
        rules_output = self.run_cmd("nft list ruleset")
        seen_rules = set()

        if not rules_output.strip():
            self.weak_rules.append({
                "rule type": "Empty ruleset",
                "description": "nftables appears to be installed but has no active ruleset.",
                "recommendation": "Ensure appropriate firewall policies are configured",
                "raw rule": None
            })
            return

        for line in rules_output.splitlines():
            line_lower = line.lower().strip()

            if re.search(r'(iifname\s+"lo"|oifname\s+"lo")', line_lower):
                continue
            if re.search(r'ct state related,established', line_lower):
                continue

            if re.search(r'accept\s*$', line_lower) and not re.search(r'dport|saddr|proto|ip|meta', line_lower):
                msg_key = f"blind_accept::{line.strip()}"
                if msg_key not in seen_rules:
                    self.weak_rules.append({
                        "rule type": "Blind accept",
                        "description": "Blind ACCEPT rule with no filters",
                        "recommendation": "Add filters like source address, protocol, or port to restrict traffic",
                        "raw rule": line.strip()
                    })
                    seen_rules.add(msg_key)

            if re.search(r'ip\s+saddr\s+(0\.0\.0\.0/0|any)', line_lower) and "accept" in line_lower:
                msg_key = f"accept_anywhere::{line.strip()}"
                if msg_key not in seen_rules:
                    self.weak_rules.append({
                        "rule type": "Accept from anywhere",
                        "description": "Accepts traffic from any IP address",
                        "recommendation": "Restrict source IPs to only trusted networks",
                        "raw rule": line.strip()
                    })
                    seen_rules.add(msg_key)

            ports = {
                22: ("SSH open", "SSH port open to the world", "Restrict SSH to trusted IPs"),
                23: ("Telnet open", "Telnet port open — insecure protocol", "Disable Telnet and use SSH"),
                3389: ("RDP open", "RDP port open — risky on public networks", "Tunnel RDP through VPN or restrict IPs"),
                21: ("FTP open", "FTP port open — insecure protocol", "Use SFTP or FTPS instead of FTP"),
                80: ("HTTP open", "HTTP port open", "Ensure web service is intended and secured"),
                443: ("HTTPS open", "HTTPS port open", "Ensure HTTPS service is required and secured")
            }

            for port, (rule_type, description, recommendation) in ports.items():
                pattern = rf'(tcp|udp)?\s*dport\s+{port}'
                if re.search(pattern, line_lower):
                    msg_key = f"dport_{port}::{line.strip()}"
                    if msg_key not in seen_rules:
                        self.weak_rules.append({
                            "rule type": rule_type,
                            "description": description,
                            "recommendation": recommendation,
                            "raw rule": line.strip()
                        })
                        seen_rules.add(msg_key)