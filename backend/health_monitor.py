"""
Health Monitor Module - WiFi Guard Project
Module 1: Network Health & Diagnostics

This module monitors the health of discovered network devices by measuring
latency and packet loss through ICMP ping operations. It is designed to be
modular for future extensions including bandwidth measurement, jitter analysis,
health scoring, and recommendations.
"""

import platform
import subprocess
import statistics
import socket
import time
import psutil
from typing import List, Dict, Optional
from scanner import NetworkScanner


class HealthMonitor:
    """
    A health monitor that measures network device health metrics.
    Currently supports latency and packet loss measurement via ICMP ping.
    """
    
    def __init__(self, ping_count: int = 2, ping_timeout: int = 1):
        """
        Initialize the health monitor.
        
        Args:
            ping_count: Number of ping packets to send per device
            ping_timeout: Timeout in seconds for each ping attempt
        """
        self.ping_count = ping_count
        self.ping_timeout = ping_timeout
        self.network_scanner = NetworkScanner()
        self.local_ip = self._get_local_ip()
    
    def _get_local_ip(self) -> str:
        """
        Get the local machine's IP address.
        
        Returns:
            Local IP address as string, or None if unable to determine
        """
        try:
            # Create a socket to determine the local IP used for external connections
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # Connect to a public DNS server (doesn't actually send data)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                return local_ip
            finally:
                s.close()
        except Exception:
            return None
    
    def _ping_device(self, ip_address: str) -> Dict:
        """
        Ping a single device and measure latency and packet loss.
        
        Args:
            ip_address: IP address of the device to ping
            
        Returns:
            Dictionary containing ping results:
            - success: bool indicating if ping was successful
            - latency_ms: float average latency in milliseconds (None if failed)
            - packet_loss_percent: float percentage of lost packets
            - sent: int number of packets sent
            - received: int number of packets received
        """
        # Determine ping command based on OS
        system = platform.system().lower()
        
        if system == "windows":
            # Windows ping command
            cmd = ["ping", "-n", str(self.ping_count), "-w", str(self.ping_timeout * 1000), ip_address]
        else:
            # Linux/Unix ping command
            cmd = ["ping", "-c", str(self.ping_count), "-W", str(self.ping_timeout), ip_address]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.ping_timeout * self.ping_count + 5
            )
            
            # Parse ping output
            if system == "windows":
                return self._parse_windows_ping(result.stdout, result.returncode)
            else:
                return self._parse_unix_ping(result.stdout, result.returncode)
                
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "latency_ms": None,
                "packet_loss_percent": 100.0,
                "sent": self.ping_count,
                "received": 0,
                "latencies": []
            }
        except Exception:
            return {
                "success": False,
                "latency_ms": None,
                "packet_loss_percent": 100.0,
                "sent": self.ping_count,
                "received": 0,
                "latencies": []
            }
    
    def _parse_windows_ping(self, output: str, returncode: int) -> Dict:
        """
        Parse Windows ping output.
        
        Args:
            output: Ping command stdout
            returncode: Ping command return code
            
        Returns:
            Dictionary with parsed ping results
        """
        lines = output.split('\n')
        
        sent = self.ping_count
        received = 0
        latencies = []
        
        for line in lines:
            # Look for reply lines with latency
            if "Reply from" in line and "time=" in line.lower():
                received += 1
                # Extract latency (Windows format: time=2ms or time<1ms)
                try:
                    if "time<" in line.lower():
                        latencies.append(0.5)  # Assume 0.5ms for <1ms
                    else:
                        time_part = line.lower().split("time=")[1].split("ms")[0]
                        latencies.append(float(time_part))
                except (IndexError, ValueError):
                    pass
        
        packet_loss_percent = ((sent - received) / sent) * 100 if sent > 0 else 100.0
        
        if latencies:
            avg_latency = statistics.mean(latencies)
        else:
            avg_latency = None
        
        return {
            "success": received > 0,
            "latency_ms": avg_latency,
            "packet_loss_percent": packet_loss_percent,
            "sent": sent,
            "received": received,
            "latencies": latencies  # Include individual latencies for jitter calculation
        }
    
    def _parse_unix_ping(self, output: str, returncode: int) -> Dict:
        """
        Parse Unix/Linux ping output.
        
        Args:
            output: Ping command stdout
            returncode: Ping command return code
            
        Returns:
            Dictionary with parsed ping results
        """
        lines = output.split('\n')
        
        sent = self.ping_count
        received = 0
        latencies = []
        
        for line in lines:
            # Look for reply lines with time
            if "bytes from" in line and "time=" in line:
                received += 1
                try:
                    time_part = line.split("time=")[1].split(" ")[0]
                    latencies.append(float(time_part))
                except (IndexError, ValueError):
                    pass
        
        packet_loss_percent = ((sent - received) / sent) * 100 if sent > 0 else 100.0
        
        if latencies:
            avg_latency = statistics.mean(latencies)
        else:
            avg_latency = None
        
        return {
            "success": received > 0,
            "latency_ms": avg_latency,
            "packet_loss_percent": packet_loss_percent,
            "sent": sent,
            "received": received,
            "latencies": latencies  # Include individual latencies for jitter calculation
        }
    
    def _calculate_jitter(self, latencies: List[float]) -> Optional[float]:
        """
        Calculate jitter from a list of latency values.
        
        Jitter is the average of the absolute differences between consecutive latency measurements.
        This measures the variation in latency over time.
        
        Args:
            latencies: List of latency values in milliseconds
            
        Returns:
            Jitter in milliseconds, or None if insufficient data
        """
        if len(latencies) < 2:
            return None
        
        # Calculate absolute differences between consecutive latencies
        differences = []
        for i in range(1, len(latencies)):
            diff = abs(latencies[i] - latencies[i-1])
            differences.append(diff)
        
        # Jitter is the average of these differences
        if differences:
            jitter = statistics.mean(differences)
            return round(jitter, 2)
        
        return None
    
    def measure_jitter(self, ip_address: str, ping_count: int = 10) -> Dict:
        """
        Measure jitter to a specific device by sending multiple pings.
        
        Args:
            ip_address: IP address to measure jitter to
            ping_count: Number of pings to send (default 10 for better jitter calculation)
            
        Returns:
            Dictionary containing:
            - jitter_ms: Jitter in milliseconds
            - latencies: List of individual latency measurements
            - avg_latency_ms: Average latency
            - success: Whether measurement was successful
        """
        # Override ping count for jitter measurement
        original_count = self.ping_count
        self.ping_count = ping_count
        
        try:
            ping_result = self._ping_device(ip_address)
            
            if ping_result.get("success") and ping_result.get("latencies"):
                jitter = self._calculate_jitter(ping_result["latencies"])
                
                return {
                    "jitter_ms": jitter,
                    "latencies": ping_result["latencies"],
                    "avg_latency_ms": ping_result["latency_ms"],
                    "success": True
                }
            else:
                return {
                    "jitter_ms": None,
                    "latencies": ping_result.get("latencies", []),
                    "avg_latency_ms": ping_result.get("latency_ms"),
                    "success": False
                }
        except Exception:
            return {
                "jitter_ms": None,
                "latencies": [],
                "avg_latency_ms": None,
                "success": False
            }
        finally:
            # Restore original ping count
            self.ping_count = original_count
    
    def monitor_devices(self, target_ip_range: str = None) -> List[Dict]:
        """
        Monitor health of all discovered devices on the network.
        
        Args:
            target_ip_range: Optional IP range to scan. If None, auto-detects local network.
            
        Returns:
            List of device health dictionaries containing:
            - ip: str IP address
            - mac: str MAC address
            - hostname: str resolved hostname
            - vendor: str device vendor
            - device_type: str detected device type
            - latency_ms: float average latency in milliseconds
            - packet_loss_percent: float percentage of lost packets
            - ping_success: bool whether device responded to ping
        """
        # Scan network to discover devices
        if target_ip_range:
            self.network_scanner.target_ip_range = target_ip_range
        
        devices = self.network_scanner.scan(verbose=False)
        
        # Monitor each device
        health_results = []
        for device in devices:
            # Check if this is the local machine
            is_local_device = self.local_ip and device["ip"] == self.local_ip
            
            if is_local_device:
                # Mark local device without pinging
                health_entry = {
                    "ip": device["ip"],
                    "mac": device["mac"],
                    "hostname": device["hostname"],
                    "vendor": device["vendor"],
                    "device_type": device["device_type"],
                    "latency_ms": None,
                    "packet_loss_percent": None,
                    "ping_success": None,
                    "is_local_device": True
                }
            else:
                # Ping remote devices
                ping_result = self._ping_device(device["ip"])
                
                health_entry = {
                    "ip": device["ip"],
                    "mac": device["mac"],
                    "hostname": device["hostname"],
                    "vendor": device["vendor"],
                    "device_type": device["device_type"],
                    "latency_ms": ping_result["latency_ms"],
                    "packet_loss_percent": ping_result["packet_loss_percent"],
                    "ping_success": ping_result["success"],
                    "is_local_device": False
                }
            
            health_results.append(health_entry)
        
        return health_results
    
    # Placeholder methods for future extensions
    def measure_bandwidth(self, ip_address: str) -> Dict:
        """
        Placeholder for bandwidth measurement.
        
        Args:
            ip_address: IP address to measure bandwidth to
            
        Returns:
            Empty dictionary - to be implemented
        """
        return {}
    
    def calculate_health_score(self, device_health: Dict) -> float:
        """
        Calculate health score for a single device based on latency and packet loss.
        
        Scoring logic:
        - Latency: 0-10ms = 100 points, 10-50ms = 80-99 points, 50-100ms = 60-79 points, 100-200ms = 40-59 points, 200-500ms = 20-39 points, >500ms = 0-19 points
        - Packet loss: 0% = 100 points, 0-1% = 90-99 points, 1-5% = 70-89 points, 5-10% = 50-69 points, 10-25% = 25-49 points, >25% = 0-24 points
        - Final score = (latency_score + packet_loss_score) / 2
        
        Args:
            device_health: Device health dictionary containing latency_ms and packet_loss_percent
            
        Returns:
            Health score from 0-100
        """
        latency = device_health.get("latency_ms")
        packet_loss = device_health.get("packet_loss_percent")
        
        # If device is unreachable, return 0
        if latency is None or packet_loss is None:
            return 0.0
        
        # Calculate latency score
        if latency <= 10:
            latency_score = 100
        elif latency <= 50:
            latency_score = 99 - ((latency - 10) / 40) * 19  # 99-80
        elif latency <= 100:
            latency_score = 79 - ((latency - 50) / 50) * 19  # 79-60
        elif latency <= 200:
            latency_score = 59 - ((latency - 100) / 100) * 19  # 59-40
        elif latency <= 500:
            latency_score = 39 - ((latency - 200) / 300) * 19  # 39-20
        else:
            latency_score = max(0, 19 - ((latency - 500) / 500) * 19)  # 19-0
        
        # Calculate packet loss score
        if packet_loss == 0:
            packet_loss_score = 100
        elif packet_loss <= 1:
            packet_loss_score = 99 - (packet_loss * 9)  # 99-90
        elif packet_loss <= 5:
            packet_loss_score = 89 - ((packet_loss - 1) / 4) * 19  # 89-70
        elif packet_loss <= 10:
            packet_loss_score = 69 - ((packet_loss - 5) / 5) * 19  # 69-50
        elif packet_loss <= 25:
            packet_loss_score = 49 - ((packet_loss - 10) / 15) * 24  # 49-25
        else:
            packet_loss_score = max(0, 24 - ((packet_loss - 25) / 75) * 24)  # 24-0
        
        # Average the two scores
        health_score = (latency_score + packet_loss_score) / 2
        return round(health_score, 1)
    
    def get_health_status(self, health_score: float) -> str:
        """
        Convert health score to status string.
        
        Args:
            health_score: Health score from 0-100
            
        Returns:
            Status string: Excellent, Good, Fair, or Poor
        """
        if health_score >= 90:
            return "Excellent"
        elif health_score >= 70:
            return "Good"
        elif health_score >= 50:
            return "Fair"
        else:
            return "Poor"
    
    def calculate_network_health(self, health_results: List[Dict]) -> Dict:
        """
        Calculate overall network health score from all non-local devices.
        
        Args:
            health_results: List of device health dictionaries
            
        Returns:
            Dictionary containing:
            - overall_score: Average health score (0-100)
            - status: Health status (Excellent, Good, Fair, Poor)
            - device_count: Number of non-local devices
            - device_scores: List of individual device scores
        """
        # Filter out local devices
        remote_devices = [d for d in health_results if not d.get("is_local_device", False)]
        
        if not remote_devices:
            return {
                "overall_score": 0.0,
                "status": "Poor",
                "device_count": 0,
                "device_scores": []
            }
        
        # Calculate health score for each remote device
        device_scores = []
        for device in remote_devices:
            score = self.calculate_health_score(device)
            device_scores.append({
                "ip": device["ip"],
                "score": score,
                "status": self.get_health_status(score)
            })
        
        # Calculate average score
        if device_scores:
            overall_score = sum(d["score"] for d in device_scores) / len(device_scores)
        else:
            overall_score = 0.0
        
        return {
            "overall_score": round(overall_score, 1),
            "status": self.get_health_status(overall_score),
            "device_count": len(remote_devices),
            "device_scores": device_scores
        }
    
    def generate_recommendations(self, device_health: Dict, jitter_data: Dict = None, throughput_data: Dict = None) -> List[Dict]:
        """
        Generate recommendations based on device health metrics.
        
        Args:
            device_health: Device health dictionary containing latency_ms, packet_loss_percent, etc.
            jitter_data: Optional jitter measurement data
            throughput_data: Optional throughput measurement data
            
        Returns:
            List of recommendation dictionaries containing:
            - severity: str (critical, warning, info)
            - metric: str (latency, packet_loss, jitter, throughput, health_score)
            - message: str Description of the issue
            - recommendation: str Suggested action
        """
        recommendations = []
        
        # Analyze latency
        latency = device_health.get("latency_ms")
        if latency is not None:
            if latency > 200:
                recommendations.append({
                    "severity": "critical",
                    "metric": "latency",
                    "message": f"High latency detected: {latency:.1f}ms",
                    "recommendation": "Check for network congestion, interference, or distance from router. Consider moving closer to the access point or reducing network load."
                })
            elif latency > 100:
                recommendations.append({
                    "severity": "warning",
                    "metric": "latency",
                    "message": f"Elevated latency detected: {latency:.1f}ms",
                    "recommendation": "Monitor for patterns. Latency may spike during peak usage. Consider QoS settings for critical applications."
                })
            elif latency > 50:
                recommendations.append({
                    "severity": "info",
                    "metric": "latency",
                    "message": f"Moderate latency: {latency:.1f}ms",
                    "recommendation": "Latency is acceptable but could be improved. Check for background processes or interference."
                })
        
        # Analyze packet loss
        packet_loss = device_health.get("packet_loss_percent")
        if packet_loss is not None:
            if packet_loss > 10:
                recommendations.append({
                    "severity": "critical",
                    "metric": "packet_loss",
                    "message": f"High packet loss detected: {packet_loss:.1f}%",
                    "recommendation": "Check network cables, router placement, and interference sources. Packet loss above 10% significantly impacts performance."
                })
            elif packet_loss > 5:
                recommendations.append({
                    "severity": "warning",
                    "metric": "packet_loss",
                    "message": f"Moderate packet loss: {packet_loss:.1f}%",
                    "recommendation": "Monitor for consistency. Packet loss may indicate intermittent connectivity issues or interference."
                })
            elif packet_loss > 1:
                recommendations.append({
                    "severity": "info",
                    "metric": "packet_loss",
                    "message": f"Minor packet loss: {packet_loss:.1f}%",
                    "recommendation": "Packet loss is within acceptable range but should be monitored for trends."
                })
        
        # Analyze jitter
        if jitter_data and jitter_data.get("success"):
            jitter = jitter_data.get("jitter_ms")
            if jitter is not None:
                if jitter > 30:
                    recommendations.append({
                        "severity": "critical",
                        "metric": "jitter",
                        "message": f"High jitter detected: {jitter:.1f}ms",
                        "recommendation": "High jitter causes inconsistent performance. Check for interference, network congestion, or faulty equipment. Consider wired connection for critical applications."
                    })
                elif jitter > 15:
                    recommendations.append({
                        "severity": "warning",
                        "metric": "jitter",
                        "message": f"Elevated jitter: {jitter:.1f}ms",
                        "recommendation": "Jitter may affect real-time applications like VoIP or gaming. Check for network stability issues."
                    })
                elif jitter > 5:
                    recommendations.append({
                        "severity": "info",
                        "metric": "jitter",
                        "message": f"Moderate jitter: {jitter:.1f}ms",
                        "recommendation": "Jitter is acceptable but could impact sensitive applications. Monitor during peak usage."
                    })
        
        # Analyze throughput (current traffic, not internet bandwidth capacity)
        if throughput_data and throughput_data.get("success"):
            download = throughput_data.get("current_traffic_download_mbps")
            upload = throughput_data.get("current_traffic_upload_mbps")
            
            # Low current traffic is informational (network is idle), not a critical issue
            if download is not None and download < 1:
                recommendations.append({
                    "severity": "info",
                    "metric": "throughput",
                    "message": f"Network is currently idle. No significant traffic detected ({download:.2f} Mbps)",
                    "recommendation": "Low current traffic indicates the network is not actively transferring data. This is normal when no applications are downloading or streaming."
                })
            elif download is not None and download > 50:
                recommendations.append({
                    "severity": "warning",
                    "metric": "throughput",
                    "message": f"High current traffic detected: {download:.2f} Mbps",
                    "recommendation": "High network utilization may indicate bandwidth-intensive applications (streaming, downloads, backups). Check if this is expected activity."
                })
            
            # Upload traffic is typically much lower than download, so only flag if unusually high
            if upload is not None and upload > 10:
                recommendations.append({
                    "severity": "warning",
                    "metric": "throughput",
                    "message": f"High upload traffic detected: {upload:.2f} Mbps",
                    "recommendation": "High upload traffic may indicate file uploads, cloud backups, or video calls. Check if this is expected activity."
                })
        
        # Analyze health score
        if not device_health.get("is_local_device"):
            health_score = self.calculate_health_score(device_health)
            if health_score < 50:
                recommendations.append({
                    "severity": "critical",
                    "metric": "health_score",
                    "message": f"Poor overall health score: {health_score:.1f}/100",
                    "recommendation": "Multiple network issues detected. Address critical recommendations above for significant improvement."
                })
            elif health_score < 70:
                recommendations.append({
                    "severity": "warning",
                    "metric": "health_score",
                    "message": f"Fair health score: {health_score:.1f}/100",
                    "recommendation": "Network performance is suboptimal. Review warnings and consider optimization steps."
                })
            elif health_score < 90:
                recommendations.append({
                    "severity": "info",
                    "metric": "health_score",
                    "message": f"Good health score: {health_score:.1f}/100",
                    "recommendation": "Network performance is good but has room for improvement. Monitor for degradation."
                })
        
        # If no issues found
        if not recommendations:
            recommendations.append({
                "severity": "info",
                "metric": "overall",
                "message": "Network metrics are within acceptable ranges",
                "recommendation": "Continue monitoring for any changes or degradation in performance."
            })
        
        return recommendations
    
    def _get_active_network_interface(self) -> Optional[str]:
        """
        Get the active network interface name.
        
        Returns:
            Interface name if found, None otherwise
        """
        try:
            # Get all network interfaces
            interfaces = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            # Try to find the interface used for external connections
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            finally:
                s.close()
            
            # Find the interface that has this IP
            for iface_name, iface_info in interfaces.items():
                for addr in iface_info:
                    if addr.family == 2 and addr.address == local_ip:
                        # Check if interface is up
                        if iface_name in stats and stats[iface_name].isup:
                            return iface_name
            
            return None
        except Exception:
            return None
    
    def measure_throughput(self, duration: float = 5.0) -> Dict:
        """
        Measure current network traffic (actual bytes transferred during measurement window).
        
        This measures the ACTUAL NETWORK TRAFFIC during the measurement window, not the
        available internet bandwidth capacity. Low values indicate the network is idle,
        not that the internet connection is slow.
        
        Args:
            duration: Measurement duration in seconds
            
        Returns:
            Dictionary containing:
            - current_traffic_download_mbps: Current download traffic in Mbps
            - current_traffic_upload_mbps: Current upload traffic in Mbps
            - measurement_type: "current_traffic" - indicates this is actual traffic, not bandwidth capacity
            - interface: Network interface name
            - duration: Measurement duration
            - success: Whether measurement was successful
        """
        interface = self._get_active_network_interface()
        
        if not interface:
            return {
                "current_traffic_download_mbps": None,
                "current_traffic_upload_mbps": None,
                "measurement_type": "current_traffic",
                "interface": None,
                "duration": duration,
                "success": False
            }
        
        try:
            # Get initial network I/O counters
            net_io_before = psutil.net_io_counters()
            time_before = time.time()
            
            # Wait for the specified duration
            time.sleep(duration)
            
            # Get final network I/O counters
            net_io_after = psutil.net_io_counters()
            time_after = time.time()
            
            # Calculate actual duration
            actual_duration = time_after - time_before
            
            # Calculate bytes transferred
            bytes_sent = net_io_after.bytes_sent - net_io_before.bytes_sent
            bytes_recv = net_io_after.bytes_recv - net_io_before.bytes_recv
            
            # Convert to Mbps (megabits per second)
            # 1 byte = 8 bits, 1 Mbps = 1,000,000 bits per second
            download_mbps = (bytes_recv * 8) / (actual_duration * 1_000_000)
            upload_mbps = (bytes_sent * 8) / (actual_duration * 1_000_000)
            
            return {
                "current_traffic_download_mbps": round(download_mbps, 2),
                "current_traffic_upload_mbps": round(upload_mbps, 2),
                "measurement_type": "current_traffic",
                "interface": interface,
                "duration": round(actual_duration, 2),
                "success": True
            }
            
        except Exception:
            return {
                "current_traffic_download_mbps": None,
                "current_traffic_upload_mbps": None,
                "measurement_type": "current_traffic",
                "interface": interface,
                "duration": duration,
                "success": False
            }


if __name__ == "__main__":
    import json
    
    # Initialize health monitor
    monitor = HealthMonitor(ping_count=4, ping_timeout=2)
    
    # Monitor devices on current network
    print("Scanning network and monitoring device health...")
    health_results = monitor.monitor_devices()
    
    # Calculate overall network health
    network_health = monitor.calculate_network_health(health_results)
    
    # Display structured output
    print("\n" + "="*100)
    print("DEVICE HEALTH RESULTS")
    print("="*100)
    print(json.dumps(health_results, indent=2))
    print("="*100)
    print(f"\nTotal devices monitored: {len(health_results)}")
    
    print("\n" + "="*100)
    print("NETWORK HEALTH SUMMARY")
    print("="*100)
    print(f"Overall Score: {network_health['overall_score']}/100")
    print(f"Status: {network_health['status']}")
    print(f"Remote Devices: {network_health['device_count']}")
    print("\nIndividual Device Scores:")
    for device_score in network_health['device_scores']:
        print(f"  {device_score['ip']}: {device_score['score']}/100 ({device_score['status']})")
    print("="*100)
    
    # Measure network throughput
    print("\nMeasuring network throughput (5 seconds)...")
    throughput = monitor.measure_throughput(duration=5.0)
    
    print("\n" + "="*100)
    print("NETWORK THROUGHPUT")
    print("="*100)
    print(f"Interface: {throughput['interface']}")
    print(f"Duration: {throughput['duration']} seconds")
    print(f"Measurement Type: {throughput['measurement_type']}")
    print(f"Current Traffic Download: {throughput['current_traffic_download_mbps']} Mbps" if throughput['success'] else "Download: Failed")
    print(f"Current Traffic Upload: {throughput['current_traffic_upload_mbps']} Mbps" if throughput['success'] else "Upload: Failed")
    print("="*100)
    
    # Measure jitter to gateway/router
    # Find the router/gateway from discovered devices
    router_device = None
    for device in health_results:
        if device.get("device_type") == "Router" and not device.get("is_local_device"):
            router_device = device
            break
    
    if router_device:
        print(f"\nMeasuring jitter to gateway ({router_device['ip']})...")
        jitter_result = monitor.measure_jitter(router_device['ip'])
        
        print("\n" + "="*100)
        print("JITTER MEASUREMENT")
        print("="*100)
        print(f"Target: {router_device['ip']}")
        print(f"Pings sent: 10")
        if jitter_result['success']:
            print(f"Jitter: {jitter_result['jitter_ms']} ms")
            print(f"Average Latency: {jitter_result['avg_latency_ms']} ms")
            print(f"Individual Latencies: {jitter_result['latencies']}")
        else:
            print("Jitter measurement failed")
        print("="*100)
    else:
        print("\nNo router/gateway found for jitter measurement")
        jitter_result = None
    
    # Generate recommendations
    print("\n" + "="*100)
    print("RECOMMENDATIONS")
    print("="*100)
    
    # Get recommendations for the router device
    if router_device:
        recommendations = monitor.generate_recommendations(router_device, jitter_result, throughput)
        print(f"\nRecommendations for {router_device['ip']} ({router_device['device_type']}):")
        for rec in recommendations:
            print(f"\n  [{rec['severity'].upper()}] {rec['metric']}")
            print(f"  Message: {rec['message']}")
            print(f"  Recommendation: {rec['recommendation']}")
    else:
        print("\nNo remote device available for recommendations")
    print("="*100)
