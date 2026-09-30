"""
Network Scanner Module - WiFi Guard Project
Module 1: Network Health & Diagnostics

This module implements ARP-based network scanning to discover devices
on the local network. It uses Scapy to craft and send ARP requests,
then collects responses to identify active devices.
"""

import time
import socket
import subprocess
import ipaddress
import psutil
import mac_vendor_lookup
from scapy.all import ARP, Ether, srp
from typing import List, Dict, Optional


class NetworkScanner:
    """
    A network scanner that uses ARP protocol to discover devices on the local network.
    """
    
    def __init__(self, target_ip_range: str = None, timeout: int = 1):
        """
        Initialize the network scanner.
        
        Args:
            target_ip_range: The IP range to scan (e.g., "192.168.1.0/24")
            timeout: Time to wait for ARP responses in seconds
        """
        self.target_ip_range = target_ip_range
        self.timeout = timeout
        self.discovered_devices = []
        self.mac_lookup = mac_vendor_lookup.MacLookup()
    
    def get_local_network_range(self, verbose: bool = False) -> str:
        """
        Automatically detect the local network subnet using psutil.
        
        This method:
        1. Gets all network interfaces on the system
        2. Finds the active interface with a default gateway
        3. Retrieves the IPv4 address and subnet mask
        4. Calculates the network range using IP address math
        
        Args:
            verbose: If True, print debug information
            
        Returns:
            Network range in CIDR notation (e.g., "10.180.177.0/24")
        
        Raises:
            Exception: If unable to detect network interface
        """
        try:
            # Get all network interfaces
            interfaces = psutil.net_if_addrs()
            if verbose:
                print(f"[*] Available interfaces: {list(interfaces.keys())}")
            
            # Get network stats to find active interfaces
            stats = psutil.net_if_stats()
            
            # Try to get default gateway to identify the active interface
            # This helps distinguish between multiple active interfaces
            try:
                # Create a socket to determine which interface is used for external connections
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    # Connect to a public DNS server (doesn't actually send data)
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    if verbose:
                        print(f"[*] Detected active IP via socket: {local_ip}")
                finally:
                    s.close()
                
                # Find the interface that has this IP
                for iface_name, iface_info in interfaces.items():
                    for addr in iface_info:
                        if addr.family == 2 and addr.address == local_ip:
                            # Found the active interface
                            subnet_mask = addr.netmask
                            
                            if verbose:
                                print(f"[*] Using network interface: {iface_name}")
                                print(f"[*] Local IP: {local_ip}")
                                print(f"[*] Subnet mask: {subnet_mask}")
                            
                            # Calculate network address
                            network = ipaddress.IPv4Network(f"{local_ip}/{subnet_mask}", strict=False)
                            
                            # For large networks (> /24), limit to local /24 subnet for faster scanning
                            if network.prefixlen < 24:
                                # Your IP is 10.0.1.117, so we'll scan 10.0.1.0/24 instead of 10.0.0.0/21
                                # This reduces from 2,046 IPs to 254 IPs - much faster!
                                ip_parts = local_ip.split('.')
                                ip_parts[3] = '0'
                                network_24 = '.'.join(ip_parts)
                                network_range = f"{network_24}/24"
                                if verbose:
                                    print(f"[*] Large network detected, limiting scan to local /24: {network_range}")
                            else:
                                network_range = str(network)
                                if verbose:
                                    print(f"[*] Detected network range: {network_range}")
                            return network_range
            except Exception as e:
                if verbose:
                    print(f"[*] Socket method failed: {e}, falling back to interface detection")
            
            # Fallback: Try to find interface with gateway
            for iface_name, iface_info in interfaces.items():
                # Check if interface is up and has IPv4 addresses
                if iface_name in stats and stats[iface_name].isup:
                    for addr in iface_info:
                        if addr.family == 2:  # AF_INET = IPv4
                            local_ip = addr.address
                            subnet_mask = addr.netmask
                            
                            # Skip loopback and APIPA addresses (169.254.x.x)
                            if local_ip.startswith('127.') or local_ip.startswith('169.254.'):
                                continue
                            
                            if verbose:
                                print(f"[*] Using network interface: {iface_name}")
                                print(f"[*] Local IP: {local_ip}")
                                print(f"[*] Subnet mask: {subnet_mask}")
                            
                            # Calculate network address using Python's ipaddress module
                            # This converts IP + mask to network address (e.g., 10.180.177.35/255.255.255.0 -> 10.180.177.0/24)
                            network = ipaddress.IPv4Network(f"{local_ip}/{subnet_mask}", strict=False)
                            
                            # For large networks (> /24), limit to local /24 subnet for faster scanning
                            if network.prefixlen < 24:
                                ip_parts = local_ip.split('.')
                                ip_parts[3] = '0'
                                network_24 = '.'.join(ip_parts)
                                network_range = f"{network_24}/24"
                                if verbose:
                                    print(f"[*] Large network detected, limiting scan to local /24: {network_range}")
                            else:
                                network_range = str(network)
                                if verbose:
                                    print(f"[*] Detected network range: {network_range}")
                            return network_range
            
            raise Exception("No active network interface with IPv4 found")
            
        except Exception as e:
            raise Exception(f"Failed to detect local network: {e}")
    
    def resolve_hostname(self, ip_address: str, verbose: bool = False) -> str:
        """
        Resolve hostname without allowing slow reverse-DNS lookups
        to hold up the network scan.
        """
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(0.1)  # Very fast timeout

            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
                return hostname
            finally:
                socket.setdefaulttimeout(old_timeout)

        except (socket.herror, socket.timeout, OSError):
            return "Unknown"
        except Exception as e:
            if verbose:
                print(f"[*] Error resolving hostname for {ip_address}: {e}")
            return "Unknown"
    
    def get_mac_vendor(self, mac_address: str, verbose: bool = False) -> str:
        """
        Get vendor/manufacturer information from MAC address using OUI lookup.
        
        OUI (Organizationally Unique Identifier) is the first 3 octets (24 bits) of a MAC address.
        IEEE assigns OUIs to manufacturers, allowing identification of device vendors.
        
        Example: MAC "c6:a7:af:16:ae:4c" -> OUI "c6:a7:af" -> Vendor "TP-Link"
        
        Args:
            mac_address: The MAC address to lookup
            verbose: If True, print debug information
            
        Returns:
            Vendor name if found, 'Unknown' otherwise
        """
        try:
            # mac_vendor_lookup library automatically extracts OUI and queries the database
            vendor = self.mac_lookup.lookup(mac_address)
            return vendor
        except Exception:
            # Silently return "Unknown" for any vendor lookup errors
            return "Unknown"
    
    def detect_device_type(self, ip, mac, hostname, vendor, gateway_ip=None):
        hostname = (hostname or "").lower()
        vendor = (vendor or "").lower()

        # 1. Gateway is always the strongest router signal
        if gateway_ip and ip == gateway_ip:
            return "Router"

        # 2. Router / network equipment
        router_keywords = [
            "router", "gateway", "access point", "wireless ap",
            "tp-link", "tplink", "netgear", "d-link", "dlink",
            "mikrotik", "ubiquiti", "cisco", "aruba",
            "huawei technologies", "zte corporation"
        ]

        if any(k in hostname or k in vendor for k in router_keywords):
            return "Router"

        # 3. Phones / tablets
        phone_keywords = [
            "iphone", "ipad", "android", "phone", "mobile",
            "samsung mobile", "oneplus", "xiaomi", "redmi",
            "oppo", "vivo", "realme", "motorola",
            "pixel", "galaxy"
        ]

        if any(k in hostname or k in vendor for k in phone_keywords):
            return "Phone"

        # 4. Computers
        computer_keywords = [
            "laptop", "desktop", "pc", "macbook",
            "windows", "computer", "notebook",
            "lenovo", "dell", "hewlett-packard",
            "acer", "asus", "msi",
            "microsoft corporation"
        ]

        if any(k in hostname or k in vendor for k in computer_keywords):
            return "Laptop/PC"

        # 5. Apple devices that couldn't be identified more specifically
        # Keep these separate rather than automatically calling them a PC.
        if "apple" in vendor or "apple" in hostname:
            return "Apple Device"

        return "Unknown"
    
    def get_gateway_ip(self, verbose: bool = False) -> str:
        """
        Get the default gateway associated with the currently active local IPv4 interface.
        """

        try:
            # Detect the local IP actually used for outbound traffic
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            finally:
                s.close()

            if verbose:
                print(f"[*] Active local IP: {local_ip}")

            # Get Windows routing table
            result = subprocess.run(
                ["route", "print", "-4"],
                capture_output=True,
                text=True,
                shell=True
            )

            if result.returncode != 0:
                return None

            candidates = []

            for line in result.stdout.splitlines():
                parts = line.split()

                # Default route format:
                # 0.0.0.0  0.0.0.0  <gateway>  <interface>  <metric>
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gateway = parts[2]
                    interface_ip = parts[3]

                    if gateway == "0.0.0.0":
                        continue

                    # Prefer the route belonging to our active interface
                    if interface_ip == local_ip:
                        metric = int(parts[4]) if parts[4].isdigit() else 9999
                        candidates.append((metric, gateway))

            if candidates:
                candidates.sort(key=lambda x: x[0])
                gateway = candidates[0][1]

                if verbose:
                    print(f"[*] Detected gateway: {gateway}")

                return gateway

            # Fallback: first valid default gateway
            for line in result.stdout.splitlines():
                parts = line.split()

                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gateway = parts[2]

                    if gateway != "0.0.0.0":
                        return gateway

        except Exception as e:
            if verbose:
                print(f"[*] Could not detect gateway: {e}")

        return None
    
    def scan(self, verbose: bool = False) -> List[Dict]:
        """
        Perform ARP scan on the target network.
        
        Args:
            verbose: If True, print debug information during scan
            
        Returns:
            List of discovered devices with IP, MAC, hostname, vendor, and device_type
        """
        # Auto-detect network range if not provided
        if not self.target_ip_range:
            if verbose:
                print("[*] No target IP range specified, auto-detecting local network...")
            self.target_ip_range = self.get_local_network_range(verbose=verbose)
        
        # Get local IP to identify our own device
        local_ip = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            finally:
                s.close()
        except Exception:
            pass
        
        # Get default gateway for device type detection
        gateway_ip = self.get_gateway_ip()
        if gateway_ip and verbose:
            print(f"[*] Default gateway: {gateway_ip}")
        
        if verbose:
            print(f"[*] Starting ARP scan on {self.target_ip_range}")
            print(f"[*] Timeout: {self.timeout} seconds")
            if local_ip:
                print(f"[*] Local device IP: {local_ip}")
        
        # Step 1: Create ARP request packet
        # ARP request asks: "Who has target IP? Tell me"
        # We use broadcast MAC (ff:ff:ff:ff:ff:ff) to reach all devices
        arp_request = ARP(pdst=self.target_ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        # Step 2: Send and receive packets
        # srp = send and receive packet at layer 2 (Ethernet)
        # timeout: how long to wait for responses
        # verbose=0: suppress Scapy output
        answered_list = srp(arp_request_broadcast, timeout=1,inter=0.01, verbose=False)[0]
        
        # Step 3: Parse responses
        # Each answered packet contains: (request, response)
        # We extract IP and MAC from the response
        self.discovered_devices = []
        for element in answered_list:
            # element[1] is the response packet
            response = element[1]
            ip = response.psrc
            mac = response.hwsrc
            
            # Skip hostname resolution for speed - set to Unknown
            hostname = "Unknown"
            
            # Get vendor information from MAC address
            if verbose:
                print(f"[*] Looking up vendor for {mac}...")
            vendor = self.get_mac_vendor(mac, verbose=verbose)
            
            # Detect device type using heuristics
            device_type = self.detect_device_type(ip, mac, hostname, vendor, gateway_ip)
            
            # Mark if this is our local device
            is_local_device = (ip == local_ip) if local_ip else False
            
            self.discovered_devices.append({
                "ip": ip, 
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor,
                "device_type": device_type,
                "is_local_device": is_local_device
            })
        
        # Step 4: Return discovered devices
        return self.discovered_devices
    
    def display_results(self, devices: List[Dict] = None):
        """
        Display discovered devices in a formatted table.
        
        Args:
            devices: List of device dictionaries to display. If None, uses self.discovered_devices
        """
        device_list = devices if devices is not None else self.discovered_devices
        
        if not device_list:
            print("[!] No devices found")
            return
        
        print("\n" + "="*120)
        print("DISCOVERED DEVICES")
        print("="*120)
        print(f"{'IP Address':<20} {'MAC Address':<20} {'Hostname':<25} {'Vendor':<30} {'Device Type':<15}")
        print("-" * 120)
        
        for device in device_list:
            print(f"{device['ip']:<20} {device['mac']:<20} {device['hostname']:<25} {device['vendor']:<30} {device['device_type']:<15}")
        
        print("="*120)


if __name__ == "__main__":
    # Example usage - auto-detect local network
    # You can also specify a range manually: NetworkScanner(target_ip_range="192.168.1.0/24")
    scanner = NetworkScanner()  # No target specified = auto-detect
    devices = scanner.scan(verbose=True)  # verbose=True for console output
    
    print("\n[*] Scan Complete")
    print(f"[*] Found {len(devices)} devices")
    
    # Display results in formatted table
    scanner.display_results(devices)
