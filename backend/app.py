"""
WiFi Guard Backend - Flask Application
Module 1: Network Health & Diagnostics API

This Flask application provides REST API endpoints for the WiFi Guard project,
including network scanning, device discovery, and threat detection.
"""

import os
import subprocess
import socket
from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv
from scanner import NetworkScanner
from health_monitor import HealthMonitor
from threat_monitor import ThreatMonitor
from google import genai

# Load environment variables from backend/.env
load_dotenv()

# Initialize the Flask application
app = Flask(__name__)

# Gemini API key
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
# Gemini AI client
gemini_client = genai.Client(api_key=GEMINI_API_KEY)


# Enable CORS for the frontend running on localhost
CORS(app, origins=[
    'http://localhost:5173',
    'http://localhost:8080',
    'http://127.0.0.1:5173',
    'http://127.0.0.1:8080',
    'https://wifi-guard-frontend-production.up.railway.app'
], supports_credentials=False)

# Global threat monitor instance
threat_monitor = ThreatMonitor()

# __name__ is a special Python variable that holds the name of the current module
# Flask uses this to determine the root path for the application (for locating templates, static files, etc.)


@app.route('/')
def home():
    """
    Home route - Basic health check endpoint.
    
    @app.route('/') decorator maps this function to the root URL path '/'
    When a GET request is made to http://127.0.0.1:49500/, this function is executed
    
    Returns:
        JSON response with a status message
    """
    # jsonify() converts Python dictionaries to JSON format and sets proper Content-Type header
    # This is the standard way to return JSON responses in Flask
    return jsonify({
        "message": "WiFi Guard Backend Running",
        "status": "active",
        "module": "Network Health & Diagnostics"
    })


@app.route('/scan')
def scan():
    try:
        # Don't clear threat events - keep them for timeline visibility
        # Only clear if explicitly requested
        # threat_monitor.threat_events.clear()
        # threat_monitor.active_threats.clear()
        # threat_monitor.suspicious_domain_alerted.clear()
        # threat_monitor._recalculate_active_threat_score()
        
        # Start packet/threat monitoring
        if not threat_monitor.monitoring:
            monitor_result = threat_monitor.start_monitoring()
        else:
            monitor_result = {
                "success": True,
                "monitoring": True
            }

        # Scan network devices
        scanner = NetworkScanner()
        devices = scanner.scan(verbose=False)
        print("[SCAN] Devices found:", devices)

        return jsonify({
            "success": True,
            "device_count": len(devices),
            "devices": devices,
            "monitoring": monitor_result.get("monitoring", False),
            "monitor_message": monitor_result.get("message")
        })

    except Exception as e:
        import traceback

        print("[SCAN ERROR]", str(e))
        traceback.print_exc()

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/network-health')
def network_health():
    """
    Network health route - Comprehensive health monitoring endpoint.
    
    @app.route('/network-health') decorator maps this function to the '/network-health' URL path
    When a GET request is made to http://127.0.0.1:49500/network-health, this function is executed
    
    Returns:
        JSON response with device health results, overall health score, throughput, jitter, and recommendations
    """
    try:
        # Create a HealthMonitor instance
        monitor = HealthMonitor(ping_count=4, ping_timeout=2)
        
        # Monitor devices on the network
        health_results = monitor.monitor_devices()
        
        # Calculate overall network health
        network_health = monitor.calculate_network_health(health_results)
        
        # Measure network throughput
        throughput = monitor.measure_throughput(duration=5.0)
        
        # Measure jitter to gateway/router
        router_device = None
        for device in health_results:
            if device.get("device_type") == "Router" and not device.get("is_local_device"):
                router_device = device
                break
        
        jitter_result = None
        if router_device:
            jitter_result = monitor.measure_jitter(router_device['ip'])
        
        # Generate recommendations for the router device
        recommendations = []
        if router_device:
            recommendations = monitor.generate_recommendations(router_device, jitter_result, throughput)
        
        # Return comprehensive health data
        return jsonify({
            "success": True,
            "device_health": health_results,
            "overall_health": {
                "score": network_health['overall_score'],
                "status": network_health['status'],
                "device_count": network_health['device_count'],
                "device_scores": network_health['device_scores']
            },
            "throughput": throughput,
            "jitter": jitter_result,
            "recommendations": recommendations
        })
    except Exception as e:
        # Return error response with 500 status code
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/start-monitoring', methods=['POST'])
def start_monitoring():
    """
    Start threat monitoring endpoint.
    
    POST /start-monitoring
    Request body (optional): {"interface": "eth0"}
    
    Returns:
        JSON response with monitoring status
    """
    try:
        # Get interface from request body if provided (safely handle empty/invalid JSON)
        data = request.get_json(silent=True) or {}
        interface = data.get('interface') if data else None
        
        # Start monitoring
        result = threat_monitor.start_monitoring(interface=interface)
        
        return jsonify(result)
    except Exception as e:
        import traceback
        print(f"Error in start_monitoring: {str(e)}")
        print(traceback.format_exc())
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/stop-monitoring', methods=['POST'])
def stop_monitoring():
    """
    Stop threat monitoring endpoint.
    
    POST /stop-monitoring
    
    Returns:
        JSON response with final monitoring statistics
    """
    try:
        result = threat_monitor.stop_monitoring()
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/threat-status')
def threat_status():
    """
    Get current threat monitoring status.
    
    GET /threat-status
    
    Returns:
        JSON response with monitoring status, threat score, severity, and statistics
    """
    try:
        status = threat_monitor.get_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/threat-events')
def threat_events():
    """
    Get detected threat events.
    
    GET /threat-events?limit=10
    
    Query parameters:
        limit: Maximum number of events to return (optional)
    
    Returns:
        JSON response with threat events
    """
    try:
        # Get limit from query parameters
        limit = request.args.get('limit', type=int)
        
        events = threat_monitor.get_threat_events(limit=limit)
        return jsonify({
            "success": True,
            "events": events,
            "count": len(events)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/device-stats')
def device_stats():
    """
    Get device statistics from packet monitoring.
    
    GET /device-stats?ip=10.0.0.1
    
    Query parameters:
        ip: IP address of the device (optional, returns all devices if not provided)
    
    Returns:
        JSON response with device statistics
    """
    try:
        # Get IP from query parameters
        ip_address = request.args.get('ip')
        
        stats = threat_monitor.get_device_stats(ip_address=ip_address)
        return jsonify({
            "success": True,
            "stats": stats
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/recent-packets')
def recent_packets():
    """
    Get recent packets from all devices or a specific device.
    
    GET /recent-packets?ip=10.0.0.1&limit=50
    
    Query parameters:
        ip: IP address of the device (optional, returns packets from all devices if not provided)
        limit: Maximum number of packets to return (default: 50)
    
    Returns:
        JSON response with recent packet activity
    """
    try:
        # Get parameters
        ip_address = request.args.get('ip')
        limit = request.args.get('limit', type=int, default=50)
        
        # Get all device stats
        all_stats = threat_monitor.get_device_stats(ip_address=None)
        
        # Collect recent packets
        packets = []
        if 'devices' in all_stats:
            for device_ip, device_data in all_stats['devices'].items():
                # Filter by IP if specified
                if ip_address and device_ip != ip_address:
                    continue
                
                # Add device context to each packet
                for packet in device_data.get('recent_packets', []):
                    packets.append({
                        'timestamp': packet['timestamp'],
                        'src_ip': packet['src_ip'],
                        'dst_ip': packet['dst_ip'],
                        'protocol': packet['protocol'],
                        'size': packet['size'],
                        'device_ip': device_ip,
                        'direction': 'outbound' if packet['src_ip'] == device_ip else 'inbound'
                    })
        
        # Sort by timestamp (newest first) and limit
        packets.sort(key=lambda x: x['timestamp'], reverse=True)
        packets = packets[:limit]
        
        return jsonify({
            "success": True,
            "packets": packets,
            "count": len(packets)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/block-website", methods=["POST"])
def block_website():
    try:
        data = request.get_json(silent=True) or {}

        destination_ip = data.get("destination_ip")
        domain = data.get("domain")

        # Resolve domain + include the triggering IP
        destination_ips = []

        if domain:
            try:
                addresses = socket.getaddrinfo(
                    domain,
                    None,
                    socket.AF_UNSPEC,
                    socket.SOCK_STREAM
                )

                destination_ips = list({
                    address[4][0]
                    for address in addresses
                    if address[4][0]
                })

                print(f"[BLOCK] Domain: {domain}")
                print(f"[BLOCK] Resolved IPs: {destination_ips}")

            except socket.gaierror:
                if destination_ip:
                    destination_ips = [destination_ip]
                else:
                    return jsonify({
                        "success": False,
                        "error": f"Could not resolve domain: {domain}"
                    }), 400

            if destination_ip and destination_ip not in destination_ips:
                destination_ips.append(destination_ip)

        elif destination_ip:
            destination_ips = [destination_ip]

        else:
            return jsonify({
                "success": False,
                "error": "Provide destination_ip or domain"
            }), 400

        blocked_ips = []
        errors = []

        for ip in destination_ips:

            outbound_name = f"WiFiGuard Block Outbound {ip}"
            inbound_name = f"WiFiGuard Block Inbound {ip}"

            # Remove old rules first
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall",
                    "delete", "rule",
                    f"name={outbound_name}"
                ],
                capture_output=True,
                text=True
            )

            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall",
                    "delete", "rule",
                    f"name={inbound_name}"
                ],
                capture_output=True,
                text=True
            )

            # BLOCK OUTBOUND
            result_out = subprocess.run(
                [
                    "netsh", "advfirewall", "firewall",
                    "add", "rule",
                    f"name={outbound_name}",
                    "dir=out",
                    "action=block",
                    f"remoteip={ip}",
                    "profile=any",
                    "enable=yes"
                ],
                capture_output=True,
                text=True
            )

            # BLOCK INBOUND
            result_in = subprocess.run(
                [
                    "netsh", "advfirewall", "firewall",
                    "add", "rule",
                    f"name={inbound_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}",
                    "profile=any",
                    "enable=yes"
                ],
                capture_output=True,
                text=True
            )

            # Verify BOTH rules were actually created
            verify_out = subprocess.run(
                [
                    "netsh", "advfirewall", "firewall",
                    "show", "rule",
                    f"name={outbound_name}"
                ],
                capture_output=True,
                text=True
            )

            verify_in = subprocess.run(
                [
                    "netsh", "advfirewall", "firewall",
                    "show", "rule",
                    f"name={inbound_name}"
                ],
                capture_output=True,
                text=True
            )

            out_created = "No rules match" not in verify_out.stdout
            in_created = "No rules match" not in verify_in.stdout

            if (
                result_out.returncode != 0
                or result_in.returncode != 0
                or not out_created
                or not in_created
            ):
                print(f"[BLOCK ERROR] IP: {ip}")
                print(f"[BLOCK ERROR] OUT: {verify_out.stdout} {verify_out.stderr}")
                print(f"[BLOCK ERROR] IN: {verify_in.stdout} {verify_in.stderr}")

                errors.append({
                    "ip": ip,
                    "outbound_error": verify_out.stderr or verify_out.stdout,
                    "inbound_error": verify_in.stderr or verify_in.stdout
                })
                continue

            # Successfully blocked
            blocked_ips.append(ip)
            threat_monitor.blocked_destinations.add(ip)

            # Remove matching active threats
            keys_to_remove = []

            for key, threat in threat_monitor.active_threats.items():
                if (
                    isinstance(threat, dict)
                    and threat.get("destination_ip") == ip
                ):
                    keys_to_remove.append(key)

            for key in keys_to_remove:
                del threat_monitor.active_threats[key]

            # Mark historical events inactive
            for event in threat_monitor.threat_events:
                if (
                    isinstance(event, dict)
                    and event.get("destination_ip") == ip
                ):
                    event["active"] = False

            threat_monitor._recalculate_active_threat_score()
            threat_monitor._recalculate_device_threat_stats()

        if not blocked_ips:
            return jsonify({
                "success": False,
                "error": "Failed to block destination",
                "details": errors
            }), 500

        return jsonify({
            "success": True,
            "domain": domain,
            "blocked_ips": blocked_ips,
            "errors": errors,
            "message": (
                f"Successfully blocked "
                f"{len(blocked_ips)} destination(s)"
            )
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/unblock-website', methods=['POST'])
def unblock_website():
    try:
        data = request.get_json(silent=True) or {}
        destination_ip = data.get('destination_ip')
        domain = data.get('domain')

        print(f"[UNBLOCK REQUEST] Domain: {domain}, IP: {destination_ip}")

        if not destination_ip and not domain:
            return jsonify({
                "success": False,
                "error": "destination_ip or domain is required"
            }), 400

        destinations = set()

        if destination_ip:
            destinations.add(destination_ip)

        if domain:
            try:
                addresses = socket.getaddrinfo(
                    domain,
                    None,
                    socket.AF_UNSPEC,
                    socket.SOCK_STREAM
                )

                for result in addresses:
                    ip = result[4][0]
                    if ip:
                        destinations.add(ip)

            except Exception:
                pass

        deleted = []

        for ip in destinations:
            rule_name_out = f"WiFiGuard Block Outbound {ip}"
            rule_name_in = f"WiFiGuard Block Inbound {ip}"

            # Delete outbound rule
            try:
                result_out = subprocess.run(
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        f"name={rule_name_out}"
                    ],
                    capture_output=True,
                    text=True
                )
                print(f"[UNBLOCK] Outbound rule result: returncode={result_out.returncode}")
            except Exception as e:
                print(f"[UNBLOCK ERROR] Outbound rule failed: {e}")
                result_out = None

            # Delete inbound rule
            try:
                result_in = subprocess.run(
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        f"name={rule_name_in}"
                    ],
                    capture_output=True,
                    text=True
                )
                print(f"[UNBLOCK] Inbound rule result: returncode={result_in.returncode}")
            except Exception as e:
                print(f"[UNBLOCK ERROR] Inbound rule failed: {e}")
                result_in = None

            if (result_out and result_out.returncode == 0) or (result_in and result_in.returncode == 0):
                deleted.append(ip)
                print(f"[UNBLOCK SUCCESS] Unblocked IP: {ip}")

            threat_monitor.blocked_destinations.discard(ip)

        threat_monitor.clear_suspicious_domain(
            domain=domain,
            destination_ip=destination_ip
        )

        return jsonify({
            "success": True,
            "message": "Website unblocked",
            "domain": domain,
            "destination_ip": destination_ip,
            "deleted": deleted
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/blocked-websites')
def blocked_websites():
    try:
        return jsonify({
            "success": True,
            "blocked": list(
                threat_monitor.blocked_destinations
            )
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/clear-threats', methods=['POST'])
def clear_threats():
    """
    Clear all threat events and reset threat monitoring state.
    
    POST /clear-threats
    
    Returns:
        JSON response with success status
    """
    try:
        threat_monitor.threat_events.clear()
        threat_monitor.active_threats.clear()
        threat_monitor.suspicious_domain_alerted.clear()
        threat_monitor._recalculate_active_threat_score()
        
        return jsonify({
            "success": True,
            "message": "All threats cleared"
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.post("/threat-explanation")
def threat_explanation():
    try:
        data = request.get_json() or {}
        threat = data.get("threat")

        if not threat:
            return jsonify({"error": "No threat data provided"}), 400

        explanation = threat_monitor._generate_ai_explanation(threat)

        return jsonify({
            "explanation": explanation
        })

    except Exception as e:
        print(f"[AI] Threat explanation error: {e}")
        return jsonify({
            "error": str(e)
        }), 500
        
@app.route('/ai/chat', methods=['POST'])
def ai_chat():
    try:
        data = request.get_json(silent=True) or {}
        question = data.get("question", "").strip()
        conversation = data.get("conversation", [])

        if not question:
            return jsonify({
                "success": False,
                "error": "Please provide a question."
            }), 400

        # Get current WiFi Guard security information
        threat_status = threat_monitor.get_status()
        threat_events = threat_monitor.get_threat_events(limit=10)
        device_stats = threat_monitor.get_device_stats(ip_address=None)

        network_context = {
        "threat_status": threat_status,
        "recent_threat_events": threat_events,
        "device_stats": device_stats,
    }

        prompt = f"""
You are the AI security assistant inside WiFi Guard.

Your job is to explain the user's network information in simple,
non-technical language.

Use ONLY the network information provided below when making claims
about the current network.

If the information does not contain enough evidence to answer a
question, say that clearly instead of inventing information.

Give practical defensive advice when appropriate.

Current WiFi Guard network data:
{network_context}

Previous conversation:
{conversation[:6]}

User question:
{question}

Use the previous conversation when the user's question refers to something discussed earlier.
Answer the user clearly and concisely.
"""

        response = gemini_client.models.generate_content(
            model="gemini-3.5-flash-lite",
            contents=prompt
        )
        

        return jsonify({
            "success": True,
            "answer": response.text
        })

    

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

if __name__ == "__main__":
    

    """
    Run the Flask development server.
    
    This block only executes when the script is run directly (not when imported as a module)
    __name__ == '__main__' is True when script is run directly, False when imported
    """
    # app.run() starts the Flask development server
    # debug=True enables auto-reload on code changes and detailed error messages
    # WARNING: debug=True should NOT be used in production environments
    app.run(debug=True, host='0.0.0.0', port=49500)
    
    # host='0.0.0.0' makes the server accessible from external network interfaces
    # (not just localhost), which is useful for testing from other devices
    # port=49500 specifies the port number the server will listen on (127.0.0.1:49500)
