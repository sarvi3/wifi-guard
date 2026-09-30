I am building a Final Year project called "WiFi Guard: An Intelligent WiFi Threat Detection & Network Health Monitoring System."

The project consists of three core modules:

1. Network Health & Diagnostics
- Scan the local WiFi/network.
- Discover connected devices.
- Display IP, MAC address, hostname, vendor (optional), bandwidth usage, latency, and packet loss.
- Detect unknown/new devices.
- Calculate a Network Health Score.

2. Attack Demonstrator
- Demonstrate ARP Spoofing (fully implemented) and optionally MITM/Evil Twin in a controlled environment using only my own devices on my own network.
- Visualize packet flow and explain the attack step by step.

3. Threat Detection & Adaptive Response
- Monitor network packets in real time.
- Detect ARP anomalies, gateway MAC changes, duplicate IPs, and suspicious behavior.
- Calculate a Threat Confidence Score by combining multiple indicators instead of relying on a single event.
- Alert the user and perform feasible host-side mitigation where possible.

An AI layer will generate plain-English explanations and threat reports across all modules.

Technology Stack:
- Backend: Python, Flask
- Packet Analysis: Scapy
- Frontend: React
- AI: OpenAI API
- Development: Windows initially, later Kali Linux if required

Important:
- I do NOT want to copy existing GitHub projects.
- I want to understand and build everything from scratch.
- Help me implement one module at a time.
- Do not generate unnecessary code or features beyond the current module.
- Explain the reasoning behind important design decisions.