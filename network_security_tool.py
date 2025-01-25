import os
import subprocess
import argparse
from datetime import datetime

def nmap_scan(target):
    """Performs an Nmap scan on the specified target and saves the results."""
    print(f"[+] Starting Nmap scan on {target}")
    try:
        scan_result = subprocess.check_output(["nmap", "-sV", "-O", target], text=True)
        print(scan_result)
        with open(f"nmap_scan_{target}.txt", "w") as f:
            f.write(scan_result)
        print("[+] Nmap scan completed. Results saved.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error during Nmap scan: {e.output}")

def capture_traffic(interface, duration):
    """Captures network traffic on the specified interface for a given duration."""
    print(f"[+] Starting traffic capture on interface {interface} for {duration} seconds")
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_file = f"traffic_capture_{timestamp}.pcap"
        subprocess.run(["tshark", "-i", interface, "-a", f"duration:{duration}", "-w", pcap_file], check=True)
        print(f"[+] Traffic capture completed. File saved: {pcap_file}")
    except Exception as e:
        print(f"[!] Error during traffic capture: {e}")

def main():
    """Main function to handle command-line arguments and invoke the appropriate functionality."""
    parser = argparse.ArgumentParser(description="Network Security Assessment Tool")
    parser.add_argument("--scan", help="Target IP or domain for Nmap scan")
    parser.add_argument("--capture", help="Network interface for traffic capture")
    parser.add_argument("--duration", type=int, default=60, help="Duration of traffic capture in seconds (default: 60)")
    
    args = parser.parse_args()

    if args.scan:
        nmap_scan(args.scan)

    if args.capture:
        capture_traffic(args.capture, args.duration)

    if not args.scan and not args.capture:
        print("[!] No operation specified. Use --help for usage information.")

if __name__ == "__main__":
    main()
