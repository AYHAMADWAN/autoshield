import socket
import threading
import re
from concurrent.futures import ThreadPoolExecutor


class PortScan:
    def __init__(self, shutdown_event, target='127.0.0.1', start_port=1, end_port=65535, timeout=0.5):
        self.target = target
        self.timeout = timeout
        self.shutdown_event = shutdown_event
        self.port_range = range(start_port, end_port + 1)
        self.open_ports = []
        self.services = {}

        if not self.is_valid_ip():
            print("Invalid IP address.")
            return

        print("Scanning for open ports...")

        self.scan_ports()

        if self.open_ports:
            print(f"Open ports: {self.open_ports}")
            
            print("Identifying services...")
            # handle shutdowns
            if self.shutdown_event.is_set():
                print(f"Could not perform service scan")
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
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)  # Configurable timeout for balancing speed and accuracy
        result = s.connect_ex((self.target, port))
        if result == 0:
            self.open_ports.append(port)
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






# def scan_port(target, port, timeout):
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.settimeout(timeout)  # Configurable timeout for balancing speed and accuracy
#     result = s.connect_ex((target, port))
#     if result == 0:
#         self.open_ports.append(port)
#     s.close()

# def scan_ports(shutdown_event, target, port_range, timeout=0.5):
#     open_ports = []
#     threads = []
#     for port in port_range:
#         if shutdown_event.is_set():
#             print(f"Stopped at port: {port}")
#             break
#         thread = threading.Thread(target=scan_port, args=(target, port, timeout, open_ports))
#         threads.append(thread)
#         thread.start()
    
#     for thread in threads:
#         thread.join()
    
#     return open_ports

# def identify_services(shutdown_event, target, ports):
#     services = {}
#     for port in ports:
#         # handle shutdowns
#         if shutdown_event.is_set():
#                 print(f"Stopped at service port: {port}")
#                 break
#         try:
#             service = socket.getservbyport(port)
#         except OSError:
#             service = "Unknown"
#         services[port] = service
#     return services

# def is_valid_ip(ip):
#     pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
#     if pattern.match(ip):
#         return all(0 <= int(octet) <= 255 for octet in ip.split("."))
#     return False

# def main(shutdown_event):
#     target = '127.0.0.1' #input("Enter target IP: ")
#     while not is_valid_ip(target):
#         print("Invalid IP address. Please enter a valid IPv4 address.")
#         target = input("Enter target IP: ")
    
#     start_port = int(input("Enter start port (default 1): ") or 1)
#     end_port = int(input("Enter end port (default 65535): ") or 65535)
#     start = time.time() # <---------------------------------------------------------------------------- TIME
#     port_range = range(start_port, end_port + 1)  # Allow user-specified port range
#     timeout = 0.5 #float(input("Enter timeout value (default 0.5s): ") or 0.5)

#     print("Scanning for open ports...")

#     open_ports = scan_ports(shutdown_event, target, port_range, timeout)
#     if open_ports:
#         print(f"Open ports: {open_ports}")
        
#         print("Identifying services...")
#         services = identify_services(shutdown_event, target, open_ports)
#         for port, service in services.items():
#             print(f"Port {port}: {service}")
#     else:
#         print("No open ports found.")
    
#     end = time.time() # <---------------------------------------------------------------------------- TIME
#     print("EXECUTION TIME: {:.10f}".format(end-start))




# Plan For Port Service Mappings:
#     Use socket.getservbyport(port) to check the common service
#     associated with that port and then use systemctl? to check
#     if that service is actually running