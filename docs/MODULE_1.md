# Module 1: Network Health & Diagnostics - Network Scanner

## Objective
Develop a network scanner to discover devices on the local WiFi/network as the foundation for the WiFi Guard project. The scanner identifies connected devices and collects essential information for network health monitoring and threat detection.

## Features Implemented

### Core Functionality
- **ARP-based Network Scanning**: Uses Address Resolution Protocol to discover devices on the local network
- **Automatic Network Detection**: Auto-detects local network subnet without manual configuration
- **Device Information Collection**:
  - IP Address
  - MAC Address
  - Hostname (via reverse DNS lookup)
  - Vendor/Manufacturer (via OUI lookup)
  - Device Type classification (Router, Laptop/PC, Phone, IoT, Unknown)

### Advanced Features
- **Smart Interface Selection**: Automatically identifies the active network interface
- **Gateway Detection**: Identifies default gateway for accurate device classification
- **Device Type Heuristics**: Multi-layered classification system using:
  - Gateway IP matching (highest priority)
  - Hostname keyword analysis
  - Vendor-based identification
- **Modular Architecture**: Clean separation between scanning logic and display logic
- **Verbose Mode**: Optional debug output for development/testing

## Technologies Used

- **Python 3.x**: Core programming language
- **Scapy**: Packet crafting and ARP scanning
- **psutil**: Network interface detection and system information
- **mac-vendor-lookup**: OUI database for vendor identification
- **ipaddress**: IP address calculations and network range determination
- **socket**: Hostname resolution and network interface detection

## Project Structure

```
PROJECT/
├── backend/
│   └── scanner.py          # Network scanner implementation
├── docs/
│   └── MODULE_1.md        # This documentation
├── frontend/              # (Placeholder for React frontend)
├── venv/                  # Python virtual environment
└── PROJECT_CONTEXT.md     # Project overview
```

## How the Scanner Works (High Level)

### 1. Network Detection
- Uses `psutil` to enumerate all network interfaces
- Creates a socket connection to Google DNS (8.8.8.8) to identify the active interface
- Extracts local IP and subnet mask from the active interface
- Calculates network range using Python's `ipaddress` module

### 2. ARP Scanning
- Crafts ARP request packets asking "Who has IP X.X.X.X?"
- Broadcasts packets to MAC address `ff:ff:ff:ff:ff:ff` to reach all devices
- Uses Scapy's `srp()` function to send and receive layer 2 packets
- Collects ARP responses from active devices

### 3. Device Information Gathering
For each discovered device:
- **Hostname**: Performs reverse DNS lookup using `socket.gethostbyaddr()`
- **Vendor**: Extracts OUI (first 3 octets of MAC) and queries IEEE database
- **Device Type**: Applies heuristic classification based on gateway status, hostname, and vendor

### 4. Output Generation
- Returns structured device data as list of dictionaries
- Optional formatted table display for console usage
- Clean separation allows integration with Flask API

## Current Output

```
[*] No target IP range specified, auto-detecting local network...
[*] Available interfaces: ['Ethernet 2', 'Local Area Connection* 1', 'Local Area Connection* 2', 'Wi-Fi', 'Bluetooth Network Connection', 'Loopback Pseudo-Interface 1']
[*] Detected active IP via socket: 10.180.177.35
[*] Using network interface: Wi-Fi
[*] Local IP: 10.180.177.35
[*] Subnet mask: 255.255.255.0
[*] Detected network range: 10.180.177.0/24
[*] Default gateway: 10.180.177.12
[*] Starting ARP scan on 10.180.177.0/24
[*] Timeout: 2 seconds
[*] Resolving hostname for 10.180.177.12...
[*] Looking up vendor for c6:a7:af:16:ae:4c...
[*] Resolving hostname for 10.180.177.35...
[*] Looking up vendor for 98:fe:3e:c2:6c:21...

[*] Scan Complete
[*] Found 2 devices

========================================================================================================================
DISCOVERED DEVICES
========================================================================================================================
IP Address           MAC Address          Hostname                  Vendor                         Device Type
------------------------------------------------------------------------------------------------------------------------
10.180.177.12        c6:a7:af:16:ae:4c    Unknown                   Unknown                        Router
10.180.177.35        98:fe:3e:c2:6c:21    LAPTOP-UIHVMS44           Intel Corporate                Laptop/PC
========================================================================================================================
```

## Challenges Faced and Solutions

### Challenge 1: Scapy Version Compatibility
**Problem**: `get_if_netmask()` function not available in installed Scapy version, causing ImportError.

**Solution**: Switched to `psutil` for network interface detection, which provides cross-platform compatibility and doesn't require C compilation on Windows.

### Challenge 2: Network Interface Selection
**Problem**: Multiple active interfaces (Ethernet, Wi-Fi) caused scanner to pick wrong interface (APIPA address 169.254.x.x instead of actual network).

**Solution**: Implemented socket-based detection by connecting to 8.8.8.8 to identify the interface actually used for external traffic.

### Challenge 3: Device Type Misclassification
**Problem**: Intel NIC vendor caused laptops to be classified as routers due to incorrect vendor matching.

**Solution**: 
- Removed Intel from PC vendor list (Intel is often NIC vendor, not device manufacturer)
- Implemented priority-based classification: Gateway IP → Hostname keywords → Vendor heuristics
- Added fallback to "Unknown" for unclassified devices

### Challenge 4: Vendor Lookup Errors
**Problem**: MAC vendor lookup library printed verbose error messages for unknown vendors, cluttering output.

**Solution**: Modified exception handling to silently return "Unknown" instead of printing error details.

### Challenge 5: API Integration
**Problem**: Scanner had direct print statements mixed with business logic, making it unsuitable for Flask API integration.

**Solution**: 
- Added `verbose` parameter to all methods
- Separated scanning logic from display logic
- Made `display_results()` accept device list as parameter
- Scanner now returns clean data structures when `verbose=False`

## Future Improvements

### Planned Enhancements
1. **Bandwidth Monitoring**: Track per-device bandwidth usage over time
2. **Latency Measurement**: Implement ping-based latency testing for each device
3. **Packet Loss Detection**: Monitor network reliability and packet loss rates
4. **Network Health Score**: Calculate composite health metric based on multiple factors
5. **Historical Tracking**: Store device discovery history to detect new/unknown devices
6. **Enhanced Device Classification**: Add more sophisticated heuristics and machine learning
7. **Cross-platform Gateway Detection**: Implement Linux/macOS gateway detection methods
8. **Performance Optimization**: Add parallel scanning for large networks
9. **Web Interface**: Integrate with Flask API and React frontend for real-time monitoring
10. **Alert System**: Notify users of new devices or suspicious activity

### Technical Debt
- Add comprehensive unit tests
- Implement logging framework instead of print statements
- Add configuration file for customizable parameters
- Optimize OUI database caching
- Add error recovery mechanisms for network failures
