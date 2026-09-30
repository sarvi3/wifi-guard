# Changelog

All notable changes to the WiFi Guard project will be documented in this file.

## [Unreleased]

### Added - Module 1: Network Health & Diagnostics

#### Network Scanner (backend/scanner.py)
- **Automatic Network Detection**
  - Auto-detects local network subnet using psutil
  - Smart interface selection via socket-based detection
  - Cross-platform network interface enumeration
  - Gateway IP detection for device classification

- **ARP-based Device Discovery**
  - Implements ARP scanning using Scapy
  - Broadcast-based device discovery on local network
  - Configurable timeout for response handling
  - Efficient single-pass scanning

- **Device Information Gathering**
  - IP address extraction from ARP responses
  - MAC address extraction from ARP responses
  - Hostname resolution via reverse DNS lookup
  - Vendor identification via OUI (Organizationally Unique Identifier) lookup
  - Device type classification using multi-layered heuristics

- **Device Type Classification**
  - Priority-based classification system:
    1. Default gateway detection → Router
    2. Hostname keyword analysis → Laptop/PC, Phone, Router
    3. Vendor-based identification → Router, Phone, Laptop/PC
    4. Fallback → Unknown
  - Comprehensive vendor databases for each device type
  - Handles edge cases (Intel NIC vendor, unknown vendors)

- **Architecture & Design**
  - Modular design with separated concerns
  - Verbose mode for development/debugging
  - Clean separation of scanning logic from display logic
  - Flask API-ready (returns structured data without side effects)
  - Comprehensive error handling with graceful fallbacks

#### Documentation
- **docs/MODULE_1.md**
  - Complete module documentation
  - Technical implementation details
  - Challenges faced and solutions
  - Future improvement roadmap

### Technologies Used
- Python 3.x
- Scapy (packet crafting and ARP scanning)
- psutil (network interface detection)
- mac-vendor-lookup (OUI database)
- ipaddress (IP calculations)
- socket (hostname resolution)

### Key Achievements
- Successfully implemented end-to-end network scanner
- Resolved cross-platform compatibility issues (Windows-specific challenges)
- Achieved accurate device type classification
- Created reusable, API-ready architecture
- Established foundation for Module 2 (Attack Demonstrator)

### Known Limitations
- Gateway detection currently Windows-specific (route print command)
- Some MAC vendors may not be in OUI database
- Device classification relies on heuristics (not 100% accurate)
- Single-threaded scanning (could be optimized for large networks)

### Next Steps
- Implement bandwidth monitoring
- Add latency and packet loss measurement
- Calculate Network Health Score
- Begin Module 2: Attack Demonstrator (ARP Spoofing)
