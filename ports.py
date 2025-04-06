import socket
import threading
import re
import time
from concurrent.futures import ThreadPoolExecutor

def scan_port(target, port, timeout, open_ports):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)  # Configurable timeout for balancing speed and accuracy
    result = s.connect_ex((target, port))
    if result == 0:
        open_ports.append(port)
    s.close()

def scan_ports(shutdown_event, target, port_range, timeout=0.5):
    open_ports = []
    threads = []
    for port in port_range:
        if shutdown_event.is_set():
            print(f"Stopped at port: {port}")
            break
        thread = threading.Thread(target=scan_port, args=(target, port, timeout, open_ports))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    return open_ports

def identify_services(shutdown_event, target, ports):
    services = {}
    for port in ports:
        # handle shutdowns
        if shutdown_event.is_set():
                print(f"Stopped at service port: {port}")
                break
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = "Unknown"
        services[port] = service
    return services

def is_valid_ip(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if pattern.match(ip):
        return all(0 <= int(octet) <= 255 for octet in ip.split("."))
    return False

def main(shutdown_event):
    target = '127.0.0.1' #input("Enter target IP: ")
    while not is_valid_ip(target):
        print("Invalid IP address. Please enter a valid IPv4 address.")
        target = input("Enter target IP: ")
    
    start_port = int(input("Enter start port (default 1): ") or 1)
    end_port = int(input("Enter end port (default 65535): ") or 65535)
    start = time.time() # <---------------------------------------------------------------------------- TIME
    port_range = range(start_port, end_port + 1)  # Allow user-specified port range
    timeout = 0.5 #float(input("Enter timeout value (default 0.5s): ") or 0.5)

    print("Scanning for open ports...")

    open_ports = scan_ports(shutdown_event, target, port_range, timeout)
    if open_ports:
        print(f"Open ports: {open_ports}")
        
        print("Identifying services...")
        services = identify_services(shutdown_event, target, open_ports)
        for port, service in services.items():
            print(f"Port {port}: {service}")
    else:
        print("No open ports found.")
    
    end = time.time() # <---------------------------------------------------------------------------- TIME
    print("EXECUTION TIME: {:.10f}".format(end-start))




# Plan For Port Service Mappings:
#     Use socket.getservbyport(port) to check the common service
#     associated with that port and then use systemctl? to check
#     if that service is actually running