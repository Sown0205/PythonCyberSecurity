import time
import argparse
import threading
from scapy.all import *

# Function to validate IP address
def is_valid_ip(ip):
    pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    if re.match(pattern, ip):
       return all(0 <= int(octet) <= 255 for octet in ip.split("."))
    return False

# Function to validate port number
def is_valid_port(port):
    return isinstance(port, int) and 1 <= port <= 65535

# Function to perform SYN scan on a single port
def syn_scan(target, port, results):
    pkt = IP(dst=target) / TCP(dport=port, flags="S")  # SYN Packet
    response = sr1(pkt, timeout=1, verbose=0)  # Send & receive response

    if response:
        if response.haslayer(TCP):
            if response[TCP].flags == 0x12:  # SYN-ACK received
                print(f"[+] Port {port} is OPEN")
                send(IP(dst=target) / TCP(dport=port, flags="R"), verbose=0)  # Send RST to close
                results.append(port)
            elif response[TCP].flags == 0x14:  # RST-ACK received
                print(f"[-] Port {port} is CLOSED")
                results.append(port)

# Multi-threaded function to scan multiple ports
def scan_ports(target, ports):
    threads = []
    results = []  # Store open/closed ports

    for port in ports:
        t = threading.Thread(target=syn_scan, args=(target, port, results))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Display message if no open/closed ports found
    if not results:
        print("\n[!] No open or closed ports found in the given range.")

# Main function to handle arguments
def main():
    parser = argparse.ArgumentParser(description="Multi-threaded SYN Port Scanner")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--ports", help="Comma-separated ports (e.g., 22,80,443)")
    parser.add_argument("--range", help="Port range (e.g., 20-100)")
    args = parser.parse_args()

    # Validate IP address
    if not is_valid_ip(args.target):
        print("Error: Invalid IP address format.")
        return

    # Determine ports to scan
    ports = set()  # Use set to avoid duplicate ports

    if args.ports:
        for port in args.ports.split(","):
            port = port.strip()
            if not port.isdigit():  # Check if input is a valid number
                print(f"Error: Invalid port '{port}'. Ports must be a number.")
                return
            port = int(port)
            if not is_valid_port(port):
                print(f"Error: Invalid port '{port}'. Port must be between 1-65535.")
                return
            ports.add(port)

    if args.range:
        try:
            if "-" not in args.range:
                raise ValueError("Invalid range format. Start port and end port must be seperated by a hyphen (-)")

            start, end = args.range.split("-")

            # Validate that start and end are numeric
            if not start.isdigit() or not end.isdigit():
                raise ValueError("Start and end ports must be numbers.")

            start, end = int(start), int(end)

            if not is_valid_port(start) or not is_valid_port(end):
                raise ValueError("Start port and end port must be in the range from 1 to 65535")
            
            if start > end:
                raise ValueError("Start port must be smaller than end port")

            ports.update(range(start, end + 1))

        except ValueError as e:
            print(f"Error: {e}")
            return
    
    # Invalid port commands 
    if not ports:
        print("Error: Please specify ports using --ports or --range.")
        return

    print(f"\nStarting SYN scan on {args.target}...\n")
    start_time = time.time()  # Start time tracking

    scan_ports(args.target, ports)

    end_time = time.time()  # End time tracking
    print(f"\nScan completed ! IP address {args.target} scanned in {round(end_time - start_time, 2)} seconds.")

if __name__ == "__main__":
    main()
