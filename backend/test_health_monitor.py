"""
Test script for health_monitor.py
"""

from health_monitor import HealthMonitor
import json

# Initialize health monitor
monitor = HealthMonitor(ping_count=4, ping_timeout=2)

# Monitor devices on current network
print("Scanning network and monitoring device health...")
health_results = monitor.monitor_devices()

# Display structured output
print("\n" + "="*100)
print("DEVICE HEALTH RESULTS")
print("="*100)
print(json.dumps(health_results, indent=2))
print("="*100)
print(f"\nTotal devices monitored: {len(health_results)}")
