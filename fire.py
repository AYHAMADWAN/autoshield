import subprocess
import re

def run_cmd(command):
    try:
        return subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        raise RuntimeError('Error while running command')

def detect_firewall():
    tools = {
        "iptables": "iptables -L",
        "ufw": "ufw status",
        "nftables": "nft list ruleset"
    }

    print("[*] Detecting installed firewall tools...\n")
    detected = []
    for name, cmd in tools.items():
        try:
            output = run_cmd(cmd)
        except Exception:
            output = None

        if output:
            print(f"[+] Detected firewall: {name}")
            detected.append(name)
    if not detected:
        print("[-] No supported firewall tool detected.")
    return detected

def check_iptables_rules():
    rules_output = run_cmd("iptables -L -n --line-numbers")
    weak_rules = []

    print("\n[*] Analyzing iptables rules...\n")
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
    default_policy_output = run_cmd("iptables -S")
    if "-P INPUT ACCEPT" in default_policy_output:
        weak_rules.append("⚠️ Default INPUT policy is ACCEPT — should be DROP")
    if "-P FORWARD ACCEPT" in default_policy_output:
        weak_rules.append("⚠️ Default FORWARD policy is ACCEPT — should be DROP or REJECT")

    return weak_rules

def check_ufw_rules():
    rules_output = run_cmd("ufw status numbered")
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

def check_nftables_rules():
    rules_output = run_cmd("nft list ruleset")
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

def main():
    firewalls = detect_firewall()

    if "iptables" in firewalls:
        weak = check_iptables_rules()
        if weak:
            print("\n[!] Weak iptables rules detected:")
            for w in weak:
                print(f"  - {w}")
        else:
            print("\n[+] No weak rules found in iptables.")
    if "ufw" in firewalls:
        weak = check_ufw_rules()
        if weak:
            print("\n[!] Weak ufw rules detected:")
            for w in weak:
                print(f"  - {w}")
        else:
            print("\n[+] No weak rules found in ufw.")
  
    if "nftables" in firewalls:
        weak = check_nftables_rules()
        if weak:
            print("\n[!] Weak nftables rules detected:")
            for w in weak:
                print(f"  - {w}")
        else:
            print("\n[+] No weak rules found in nftables.")

    
    

if __name__ == "__main__":
    main()