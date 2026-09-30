"""
Threat Monitor Module - WiFi Guard Project

Module 3: Threat Detection & Adaptive Response
"""
import os
import requests
import threading
from dotenv import load_dotenv
import time
import socket
from urllib.parse import urlparse

from datetime import datetime
from typing import Dict, List, Optional

from scapy.all import (
    sniff,
    IP,
    TCP,
    UDP,
    ICMP,
    ARP,
    Ether,
    DNS,
    Raw,
)
from scapy.error import Scapy_Exception

load_dotenv()

GOOGLE_SAFE_BROWSING_API_KEY = os.getenv(
    "GOOGLE_SAFE_BROWSING_API_KEY"
)

import logging

threat_logger = logging.getLogger("ThreatMonitor")
threat_logger.setLevel(logging.WARNING)

file_handler = logging.FileHandler(
    "threat_events.log",
    mode="w"
)

file_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(message)s")
)

threat_logger.handlers.clear()
threat_logger.addHandler(file_handler)
threat_logger.propagate = False

class ThreatMonitor:
    """
    Real-time packet monitor for WiFi Guard.
    """

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.monitoring = False

        self.packet_count = 0
        self.captured_packets: List[Dict] = []
        self.max_packets = 1000

        self.monitor_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()

        self.error_message: Optional[str] = None
        self.start_time: Optional[datetime] = None

        # ARP monitoring
        self.gateway_mac: Optional[str] = None
        self.gateway_ip: Optional[str] = None
        self.ip_mac_mapping: Dict[str, str] = {}
        self.ip_mac_history: Dict[str, List[str]] = {}
        self.arp_spoof_alert_cooldown: Dict[str, float] = {}

        # Threat events
        self.threat_events: List[Dict] = []
        self.max_threat_events = 100

        # Active threats are separate from historical events.
        self.active_threats: Dict[str, Dict] = {}

        # Threat scoring
        self.threat_score = 0
        self.severity = "SAFE"
        self.total_threats = 0

        # Per-device statistics
        self.device_stats: Dict[str, Dict] = {}
        self.max_device_packets = 200

        # DNS / hostname mapping
        self.ip_hostname_mapping: Dict[str, Dict] = {}
        self.dns_request_clients: Dict[str, Dict] = {}
        self.hostname_mapping_ttl = 300

        # Prevent duplicate alerts during one monitoring session
        self.suspicious_domain_alerted = set()

        # IPs currently blocked by WiFi Guard
        self.blocked_destinations = set()

        # =========================================================
        # WEBSITE DETECTION
        # =========================================================

        # Google Safe Browsing cache
        # key -> {"unsafe": bool, "timestamp": float}
        self.safe_browsing_cache = {}

        # Local website-analysis cache
        # key -> {"score": int, "reasons": list, "timestamp": float}
        self.website_analysis_cache = {}

        # Prevent repeated Google checks for the same hostname
        self.website_check_in_progress = set()

    # =========================================================
    # PACKET HANDLER
    # =========================================================

    def _packet_handler(self, packet) -> None:
        if self.stop_event.is_set():
            return

        self.packet_count += 1

        src_ip = self._get_src_ip(packet)
        dst_ip = self._get_dst_ip(packet)

        hostname = None
        mapped_ip = None

        # Check existing IP -> hostname mapping.
        for candidate_ip in (dst_ip, src_ip):
            if candidate_ip:
                hostname = self._get_hostname_from_mapping(candidate_ip)
                if hostname:
                    mapped_ip = candidate_ip
                    break

        # Try TLS / QUIC hostname detection.
        observed_url = self._extract_http_url(packet)

        if observed_url:
            hostname = observed_url.split("://", 1)[1].split("/", 1)[0]

        if not hostname:
            hostname = self._extract_tls_sni_hostname(packet)



        # Associate recent DNS request with subsequent traffic
        # from the same device.
        if not hostname and src_ip:
            now = datetime.now().timestamp()

            recent_requests = [
                (domain, info)
                for domain, info in self.dns_request_clients.items()
                if info.get("ip") == src_ip
                and now - info.get("timestamp", 0) <= 10
            ]

            if recent_requests:
                recent_requests.sort(
                    key=lambda item: item[1].get("timestamp", 0),
                    reverse=True,
                )
                hostname = recent_requests[0][0]

        # =====================================================
        # DNS REQUEST
        # =====================================================

        if packet.haslayer(DNS) and packet.haslayer(UDP):
            dns_layer = packet[DNS]

            if dns_layer.qr == 0 and dns_layer.qd:
                try:
                    qname = dns_layer.qd.qname

                    if isinstance(qname, bytes):
                        requested_domain = (
                            qname.decode(
                                "utf-8",
                                errors="ignore",
                            )
                            .rstrip(".")
                            .lower()
                        )
                    else:
                        requested_domain = (
                            str(qname)
                            .rstrip(".")
                            .lower()
                        )

                    # Ignore local mDNS / DNS-SD names.
                    if requested_domain.endswith(".local"):
                        requested_domain = None

                    if requested_domain:
                        try:
                            results = socket.getaddrinfo(
                                requested_domain,
                                443,
                                socket.AF_UNSPEC,
                                socket.SOCK_STREAM,
                            )

                            for result in results:
                                resolved_ip = result[4][0]

                                if resolved_ip:
                                    self._update_ip_hostname_mapping(
                                        resolved_ip,
                                        requested_domain,
                                    )

                        except Exception:
                            pass

                        self.dns_request_clients[requested_domain] = {
                            "ip": src_ip,
                            "mac": self._get_src_mac(packet),
                            "timestamp": datetime.now().timestamp(),
                        }

                except Exception:
                    pass

        # =====================================================
        # DNS RESPONSE
        # =====================================================

        dns_hostname = self._extract_dns_hostname(packet)
        if dns_hostname:
            hostname = dns_hostname

        normalized_dns_hostname = (
            dns_hostname.lower().rstrip(".")
            if dns_hostname
            else ""
        )

        
    
        # =====================================================
        # SUSPICIOUS WEBSITE / IP DETECTION
        # =====================================================

        # =====================================================
        # DIRECT IP ACCESS
        # =====================================================

        # An unknown public IP is NOT automatically a threat.
        # It is only recorded as normal network traffic.
        # Actual threats should come from suspicious hostname analysis
        # or Google Safe Browsing.

        if dst_ip and not hostname:
            try:
                socket.inet_aton(dst_ip)

                # Do NOT create a threat just because the destination
                # is a public IP. Many legitimate services use CDNs
                # and connections without an immediately resolved hostname.

                print(f"[INFO] Public IP traffic observed: {dst_ip}")

            except OSError:
                pass

        
        # =====================================================
        # UPDATE HOSTNAME MAPPING
        # =====================================================

        if hostname and not mapped_ip:
            remote_ip = None

            if packet.haslayer(TCP):
                if packet[TCP].dport == 443:
                    remote_ip = dst_ip
                elif packet[TCP].sport == 443:
                    remote_ip = src_ip

            elif packet.haslayer(UDP):
                if packet[UDP].dport == 443:
                    remote_ip = dst_ip
                elif packet[UDP].sport == 443:
                    remote_ip = src_ip

            if remote_ip:
                self._update_ip_hostname_mapping(
                    remote_ip,
                    hostname,
                )

        if not hostname:
            for candidate_ip in (dst_ip, src_ip):
                if candidate_ip:
                    hostname = self._get_hostname_from_mapping(candidate_ip)
                    if hostname:
                        break

        # Fallback: associate recent DNS request from this device
        # with its following HTTPS/QUIC traffic.
        if not hostname and src_ip:
            now = datetime.now().timestamp()

            recent_dns = [
                (domain, info)
                for domain, info in self.dns_request_clients.items()
                if info.get("ip") == src_ip
                and now - info.get("timestamp", 0) <= 10
            ]

            if recent_dns:
                recent_dns.sort(
                    key=lambda item: item[1].get("timestamp", 0),
                    reverse=True,
                )

                hostname = recent_dns[0][0]
        
        normalized_hostname = (
            hostname.lower().rstrip(".")
            if hostname
            else ""
        )

        detected_suspicious_domain = None
        detected_website_reason = None
        detected_website_score = 0

        # =====================================================
        # SUSPICIOUS WEBSITE ANALYSIS
        # =====================================================

        safe_browsing_target = observed_url

        if not safe_browsing_target and normalized_hostname:
            safe_browsing_target = (
                f"https://{normalized_hostname}/"
            )

        if safe_browsing_target:
            # -------------------------------------------------
            # FAST LOCAL ANALYSIS
            # -------------------------------------------------

            website_analysis = self.analyze_website(
                safe_browsing_target
            )

            if website_analysis["suspicious"]:

                detected_suspicious_domain = (
                    safe_browsing_target
                )

                detected_website_score = (
                    website_analysis["score"]
                )

                detected_website_reason = (
                    "Local website analysis: "
                    + "; ".join(
                        website_analysis["reasons"]
                    )
                )

                print(
                    "[THREAT] Suspicious website detected: "
                    f"{safe_browsing_target}"
                )
                print(f"[THREAT] Hostname: {hostname}")

                threat_logger.warning(
                    f"[THREAT] Suspicious website detected: {safe_browsing_target}"
                )
                threat_logger.warning(f"[THREAT] Hostname: {hostname}")

                print(
                    "[Website Analysis] "
                    f"Risk score: {detected_website_score}/100"
                )

                print(
                    "[Website Analysis] "
                    f"{detected_website_reason}"
                )

            # -------------------------------------------------
            # GOOGLE SAFE BROWSING
            # -------------------------------------------------
            #
            # Always check Google Safe Browsing for known threats
            # regardless of local analysis results
            #
            if self.check_safe_browsing(
                safe_browsing_target
            ):

                detected_suspicious_domain = (
                    safe_browsing_target
                )

                detected_website_score = max(
                    detected_website_score, 100
                )

                detected_website_reason = (
                    "Google Safe Browsing flagged "
                    f"{safe_browsing_target}"
                )

                print(
                    "[THREAT] Google Safe Browsing flagged: "
                    f"{safe_browsing_target}"
                )

        # Also check just the hostname against Google Safe Browsing
        # in case we only have a hostname but no full URL
        if normalized_hostname and not detected_suspicious_domain:
            hostname_check = f"https://{normalized_hostname}/"
            if self.check_safe_browsing(hostname_check):
                detected_suspicious_domain = hostname_check
                detected_website_score = 100
                detected_website_reason = (
                    f"Google Safe Browsing flagged {normalized_hostname}"
                )
                print(
                    "[THREAT] Google Safe Browsing flagged hostname: "
                    f"{normalized_hostname}"
                )


        # Do not generate another alert for already blocked traffic.
        if dst_ip in self.blocked_destinations:
            print(f"[BLOCKED] Outbound traffic blocked: {dst_ip}")
            return

        alert_key = (
            detected_suspicious_domain.lower().rstrip(".")
            if detected_suspicious_domain
            else ""
        )

        if alert_key and alert_key not in self.suspicious_domain_alerted:
            self.suspicious_domain_alerted.add(alert_key)
            self.suspicious_domain_alerted.add(
                detected_suspicious_domain
            )

            detected_hostname = (
                detected_suspicious_domain
                .split("://", 1)[-1]
                .split("/", 1)[0]
                .lower()
                .rstrip("."
                )
            )

            # Try to get IP from mapping first
            threat_destination_ip = next(
                (
                    ip
                    for ip, mapping in self.ip_hostname_mapping.items()
                    if mapping.get("hostname", "").lower().rstrip(".")
                    == detected_hostname
                ),
                None,
            )

            # If no IP in mapping, try to resolve it now
            if not threat_destination_ip and detected_hostname:
                try:
                    results = socket.getaddrinfo(
                        detected_hostname,
                        443,
                        socket.AF_UNSPEC,
                        socket.SOCK_STREAM,
                    )
                    if results:
                        threat_destination_ip = results[0][4][0]
                        # Update mapping for future use
                        self._update_ip_hostname_mapping(
                            threat_destination_ip,
                            detected_hostname,
                        )
                except Exception:
                    pass

            # Fallback to dst_ip if still no IP
            if not threat_destination_ip:
                threat_destination_ip = dst_ip

            # Use the detected hostname as the blocking target.
            threat_domain = detected_hostname

            self._add_threat_event(
            threat_type="suspicious_website",
            source_ip=src_ip,
            source_mac=self._get_src_mac(packet),
            destination_ip=threat_destination_ip,
            reason=(
                detected_website_reason
                or
                f"Suspicious website detected: "
                f"{detected_suspicious_domain}"
            ),
            severity=(
                "critical"
                if detected_website_score >= 80
                else "warn"
            ),
            risk_score=detected_website_score,
            hostname=detected_hostname,
        )


        if self.packet_count % 100 == 0:
            self._cleanup_expired_mappings()

        # =====================================================
        # PACKET INFO
        # =====================================================

        packet_info = {
            "timestamp": datetime.now().isoformat(),
            "packet_id": self.packet_count,
            "protocol": self._get_protocol(packet),
            "size": len(packet),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_mac": self._get_src_mac(packet),
            "dst_mac": self._get_dst_mac(packet),
            "hostname": hostname,
        }

        self.captured_packets.append(packet_info)

        if len(self.captured_packets) > self.max_packets:
            self.captured_packets.pop(0)

        self._update_device_stats(packet_info)

        if packet.haslayer(ARP):
            self._analyze_arp_packet(packet)

    def analyze_website(self, target: str) -> Dict:
        """
        Fast local suspicious-website analysis.

        This does NOT prove that a website is malicious.
        It identifies URL/hostname characteristics that deserve
        further investigation.

        Returns:
            {
                "suspicious": bool,
                "score": int,
                "reasons": List[str]
            }
        """

        if not target:
            return {
                "suspicious": False,
                "score": 0,
                "reasons": []
            }

        # -----------------------------------------------------
        # Cache local analysis
        # -----------------------------------------------------
        cache_key = target.lower().rstrip("/")

        cached = self.website_analysis_cache.get(cache_key)

        if cached and time.time() - cached["timestamp"] < 900:
            return {
                "suspicious": cached["score"] >= 20,
                "score": cached["score"],
                "reasons": cached["reasons"]
            }

        # -----------------------------------------------------
        # Normalize target
        # -----------------------------------------------------
        test_url = target

        if not test_url.startswith(("http://", "https://")):
            test_url = f"https://{test_url}"

        try:
            parsed = urlparse(test_url)
        except Exception:
            return {
                "suspicious": False,
                "score": 0,
                "reasons": []
            }

        hostname = (parsed.hostname or "").lower().rstrip(".")
        path = parsed.path or ""
        query = parsed.query or ""

        if not hostname:
            return {
                "suspicious": False,
                "score": 0,
                "reasons": []
            }

        score = 0
        reasons = []

        # =====================================================
        # 1. IP ADDRESS USED AS WEBSITE
        # =====================================================

        try:
            socket.inet_aton(hostname)

            score += 25
            reasons.append(
                "Website uses an IP address instead of a domain"
            )

        except OSError:
            pass

        # =====================================================
        # 2. PUNYCODE / IDN
        # =====================================================

        if "xn--" in hostname:
            score += 35
            reasons.append(
                "Hostname contains punycode (xn--)"
            )

        # =====================================================
        # 3. USERINFO / @ SYMBOL
        # =====================================================

        if "@" in test_url:
            score += 30
            reasons.append(
                "URL contains '@' user-information syntax"
            )

        # =====================================================
        # 4. VERY LONG HOSTNAME
        # =====================================================

        if len(hostname) > 60:
            score += 5
            reasons.append(
                "Hostname is unusually long"
            )

        # =====================================================
        # 5. MANY SUBDOMAINS
        # =====================================================

        labels = hostname.split(".")

        if len(labels) >= 6:
            score += 5
            reasons.append(
                "Hostname contains many subdomains"
            )

        # =====================================================
        # 6. SUSPICIOUS SECURITY / ACCOUNT KEYWORDS
        # =====================================================

        suspicious_keywords = {
            "login",
            "signin",
            "verify",
            "verification",
            "secure",
            "security",
            "account",
            "update",
            "confirm",
            "password",
            "credential",
            "wallet",
            "payment",
            "billing",
            "recover",
            "unlock",
            "authenticate",
        }

        hostname_text = hostname.replace("-", ".")
        matched_keywords = []

        for keyword in suspicious_keywords:
            if keyword in hostname_text:
                matched_keywords.append(keyword)

        if matched_keywords:
            # Don't give an enormous score just because a
            # legitimate website contains one common word.
            keyword_score = min(20, len(matched_keywords) * 5)

            score += keyword_score

            reasons.append(
                "Suspicious security/account keyword(s): "
                + ", ".join(matched_keywords[:4])
            )

        # =====================================================
        # 7. VERY LONG URL
        # =====================================================

        if len(test_url) > 250:
            score += 55
            reasons.append(
                "URL is unusually long"
            )

        # =====================================================
        # 8. VERY LARGE QUERY STRING
        # =====================================================

        if len(query) > 200:
            score += 5
            reasons.append(
                "URL contains an unusually large query string"
            )

        # =====================================================
        # 9. EXCESSIVE URL ENCODING
        # =====================================================

        encoded_count = test_url.count("%")

        if encoded_count >= 8:
            score += 15
            reasons.append(
                "URL contains heavy percent-encoding"
            )

        # =====================================================
        # 10. SUSPICIOUS PATH WORDS
        # =====================================================

        suspicious_path_keywords = {
            "login",
            "signin",
            "verify",
            "verification",
            "password",
            "credential",
            "payment",
            "wallet",
            "account",
            "recover",
            "unlock",
        }

        path_lower = path.lower()

        matched_path_keywords = [
            keyword
            for keyword in suspicious_path_keywords
            if keyword in path_lower
        ]

        if matched_path_keywords:
            score += min(
                15,
                len(matched_path_keywords) * 5
            )

            reasons.append(
                "Suspicious path keyword(s): "
                + ", ".join(matched_path_keywords[:3])
            )

        # =====================================================
        # 11. SUSPICIOUS TLD PATTERNS
        # =====================================================

        suspicious_tlds = {
            ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz",
            ".cc", ".pw", ".biz", ".info", ".download", ".racing",
            ".science", ".win", ".trade", ".accountants", ".cricket",
            ".fit", ".date", ".review", ".tech", ".online", ".site",
            ".work", ".world", ".zip", ".mov", ".mp4", ".party",
            ".fun", ".club", ".pro", ".wang", ".ren", ".kim",
            ".loan", ".win", ".racing", ".click", ".country",
            ".stream", ".gdn", ".icu", ".cyou"
        }

        tld = hostname.split(".")[-1].lower() if "." in hostname else ""

        if f".{tld}" in suspicious_tlds:
            score += 20
            reasons.append(
                f"Uses suspicious TLD: .{tld}"
            )

        # =====================================================
        # 12. NUMERIC DOMAINS (LOTS OF NUMBERS)
        # =====================================================

        numeric_count = sum(c.isdigit() for c in hostname)
        if numeric_count > len(hostname) * 0.4:
            score += 15
            reasons.append(
                "Hostname contains excessive numbers"
            )

        # =====================================================
        # 13. SUSPICIOUS CHARACTER PATTERNS
        # =====================================================

        if hostname.count("-") > 6:
            score += 5
            reasons.append(
                "Hostname contains excessive hyphens"
            )

        # =====================================================
        # 14. BRAND IMPERSONATION CHECK
        # =====================================================

        popular_brands = {
            "google", "facebook", "amazon", "apple", "microsoft",
            "netflix", "paypal", "ebay", "twitter", "instagram",
            "linkedin", "yahoo", "outlook", "hotmail", "gmail",
            "bank", "chase", "wells", "citibank", "hsbc"
        }

        legitimate_brand_domains = {
            "google.com","google.net",
            "google.org","google.co.in",
            "googleapis.com",
            "googleusercontent.com",
            "googlevideo.com",
            "google-analytics.com",
            "googlesyndication.com",
            "doubleclick.net",
            "facebook.com",
            "facebook.net",
            "amazon.com",
            "amazonaws.com","amazon.dev","amazon.in",
            "apple.com",
            "apple.com.cn",
            "microsoft.com",
            "microsoftonline.com","s-microsoft.com",
            "office.com",
            "microsoft.com",
            "microsoftonline.com",
            "microsoft.com",
            "office365.com","cloudapp.azure.com",
            "live.com",
            "windows.net",
            "azure.com",
            "azureedge.net",
            "msftauth.net",
            "msedge.net",
            "ax-msedge.net",
            "cloud.microsoft",
            "netflix.com",
            "paypal.com",
            "ebay.com",
            "twitter.com",
            "twimg.com","ads-twitter.com","t.co",
            "instagram.com",
            "cdninstagram.com",
            "linkedin.com",
            "yahoo.com",
            "yahoo.net",
            "outlook.com",
            "outlook.office.com",
            "hotmail.com",
            "gmail.com",
            "360safe.com",
            "360.cn",
            "qihucdn.com",
        }

        hostname_parts = hostname.split(".")

        # Check whether hostname belongs to known legitimate infrastructure.
        is_legitimate_infrastructure = any(
            hostname == domain
            or hostname.endswith("." + domain)
            for domain in legitimate_brand_domains
        )

        if not is_legitimate_infrastructure:

            # Only treat the brand as impersonation when it appears
            # in the main domain name, not an arbitrary subdomain.
            if len(hostname_parts) >= 2:
                main_domain = hostname_parts[-2].lower()
            else:
                main_domain = hostname_parts[0].lower()

            for brand in popular_brands:

                if (
                    main_domain == brand
                    or main_domain.startswith(brand + "-")
                    or main_domain.endswith("-" + brand)
                ):
                    score += 25

                    reasons.append(
                        f"Potential brand impersonation: contains '{brand}'"
                    )

                    break

        # =====================================================
        # FINAL RESULT
        # =====================================================

        score = min(score, 100)

        result = {
            "suspicious": score >= 20,  # Lowered threshold for testing
            "score": score,
            "reasons": reasons,
        }

        self.website_analysis_cache[cache_key] = {
            "score": score,
            "reasons": reasons,
            "timestamp": time.time(),
        }

        return result
    
    def check_safe_browsing(self, domain: str) -> bool:
        if not GOOGLE_SAFE_BROWSING_API_KEY or not domain:
            return False

        cache_key = domain.lower().rstrip(".")

        cached = self.safe_browsing_cache.get(cache_key)
        if cached and time.time() - cached["timestamp"] < 300:
            return cached["unsafe"]

        url = (
            "https://safebrowsing.googleapis.com/v4/"
            f"threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        )

        test_url = domain
        if not test_url.startswith(("http://", "https://")):
            test_url = f"https://{test_url}"

        payload = {
            "client": {
                "clientId": "wifiguard",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": test_url}]
            }
        }

        try:
            response = requests.post(url, json=payload, timeout=5)

            unsafe = (
                response.ok
                and bool(response.json().get("matches"))
            )

            self.safe_browsing_cache[cache_key] = {
                "unsafe": unsafe,
                "timestamp": time.time(),
            }

            return unsafe

        except requests.RequestException:
            return False

    def check_safe_browsing_observation(self, hostname, observed_url=None):
        """
        Check the most specific URL we actually observed.
        Falls back to hostname only when no URL is available.
        """
        if observed_url:
            return self.check_safe_browsing(observed_url)

        if hostname:
            hostname = hostname.lower().rstrip(".")
            return self.check_safe_browsing(f"https://{hostname}/")

        return False
    # =========================================================
    # PACKET HELPERS
    # =========================================================

    def _get_protocol(self, packet) -> str:
        if packet.haslayer(ARP):
            return "ARP"
        if packet.haslayer(ICMP):
            return "ICMP"
        if packet.haslayer(TCP):
            return "TCP"
        if packet.haslayer(UDP):
            return "UDP"
        if packet.haslayer(IP):
            return "IP"
        return "OTHER"

    def _get_src_ip(self, packet) -> Optional[str]:
        try:
            if IP in packet:
                return packet[IP].src
        except Exception:
            pass
        return None

    def _get_dst_ip(self, packet) -> Optional[str]:
        try:
            if IP in packet:
                return packet[IP].dst
        except Exception:
            pass
        return None

    def _get_src_mac(self, packet) -> Optional[str]:
        if packet.haslayer(ARP):
            return packet[ARP].hwsrc
        if packet.haslayer(Ether):
            return packet[Ether].src
        return None

    def _get_dst_mac(self, packet) -> Optional[str]:
        if packet.haslayer(ARP):
            return packet[ARP].hwdst
        if packet.haslayer(Ether):
            return packet[Ether].dst
        return None

    # =========================================================
    # DNS
    # =========================================================

    def _extract_dns_hostname(self, packet) -> Optional[str]:
        try:
            if not (
                packet.haslayer(DNS)
                and packet.haslayer(UDP)
            ):
                return None

            dns_layer = packet[DNS]

            if (
                dns_layer.qr != 1
                or not dns_layer.qd
                or dns_layer.qdcount <= 0
            ):
                return None

            qname = dns_layer.qd.qname

            if isinstance(qname, bytes):
                hostname = (
                    qname.decode(
                        "utf-8",
                        errors="ignore",
                    )
                    .rstrip(".")
                )
            else:
                hostname = str(qname).rstrip(".")

            if not hostname or not dns_layer.an:
                return None

            cname_map = {}

            for answer in dns_layer.an:
                try:
                    if answer.type == 5:
                        alias = answer.rrname
                        target = answer.rdata

                        if isinstance(alias, bytes):
                            alias = alias.decode(
                                "utf-8",
                                errors="ignore",
                            ).rstrip(".")
                        else:
                            alias = str(alias).rstrip(".")

                        if isinstance(target, bytes):
                            target = target.decode(
                                "utf-8",
                                errors="ignore",
                            ).rstrip(".")
                        else:
                            target = str(target).rstrip(".")

                        if alias and target:
                            cname_map[alias.lower()] = target.lower()

                except Exception:
                    continue

            resolved_hostname = hostname.lower()
            visited = set()

            while resolved_hostname in cname_map:
                if resolved_hostname in visited:
                    break

                visited.add(resolved_hostname)
                resolved_hostname = cname_map[resolved_hostname]

            for answer in dns_layer.an:
                try:
                    if answer.type in (1, 28):
                        ip_address = answer.rdata

                        if ip_address:
                            self._update_ip_hostname_mapping(
                                str(ip_address),
                                resolved_hostname,
                            )
                except Exception:
                    continue

            return resolved_hostname

        except Exception:
            return None

    # =========================================================
    # TLS / QUIC
    # =========================================================

    def _extract_http_url(self, packet) -> Optional[str]:
        try:
            if not packet.haslayer(TCP) or not packet.haslayer(Raw):
                return None

            tcp_layer = packet[TCP]

            if tcp_layer.dport != 80:
                return None

            payload = packet[Raw].load.decode(
                "utf-8",
                errors="ignore",
            )

            lines = payload.split("\r\n")

            if not lines:
                return None

            request_line = lines[0].split(" ")

            if len(request_line) < 2:
                return None

            method = request_line[0].upper()

            if method not in {
                "GET",
                "POST",
                "HEAD",
                "PUT",
                "DELETE",
                "OPTIONS",
                "PATCH",
            }:
                return None

            path = request_line[1]

            host = None

            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    break

            if not host:
                return None

            if path.startswith(("http://", "https://")):
                return path

            return f"http://{host}{path}"

        except Exception:
            return None

    def _extract_tls_sni_hostname(
    self,
    packet,
    ) -> Optional[str]:
        try:
            dst_ip = self._get_dst_ip(packet)

            if packet.haslayer(TCP) and packet.haslayer(Raw):
                tcp_layer = packet[TCP]
                payload = packet[Raw].load

                if tcp_layer.dport == 443 or tcp_layer.sport == 443:
                    if len(payload) >= 5 and payload[0] == 22:
                        hostname = self._parse_tls_clienthello(payload)

                        if hostname:
                            return hostname

                        if dst_ip:
                            return self._get_hostname_from_mapping(
                                dst_ip
                            )

            elif packet.haslayer(UDP) and packet.haslayer(Raw):
                udp_layer = packet[UDP]
                payload = packet[Raw].load

                if udp_layer.dport == 443 or udp_layer.sport == 443:
                    hostname = self._parse_quic_clienthello(payload)

                    if hostname:
                        return hostname

                    if dst_ip:
                        return self._get_hostname_from_mapping(
                            dst_ip
                        )

        except Exception:
            pass

        return None

    def _parse_tls_clienthello(
        self,
        payload: bytes,
    ) -> Optional[str]:
        try:
            if len(payload) < 5:
                return None

            if payload[0] != 22:  # Handshake
                return None

            record_length = int.from_bytes(
                payload[3:5],
                "big",
            )

            if len(payload) < 5 + record_length:
                return None

            offset = 5

            # TLS Handshake header
            if len(payload) < offset + 4:
                return None

            if payload[offset] != 1:  # ClientHello
                return None

            handshake_length = int.from_bytes(
                payload[offset + 1:offset + 4],
                "big",
            )

            offset += 4

            if len(payload) < offset + handshake_length:
                return None

            # ClientHello version
            if len(payload) < offset + 2:
                return None

            offset += 2

            # Random
            if len(payload) < offset + 32:
                return None

            offset += 32

            # Session ID
            if len(payload) < offset + 1:
                return None

            session_id_length = payload[offset]
            offset += 1 + session_id_length

            # Cipher suites
            if len(payload) < offset + 2:
                return None

            cipher_suites_length = int.from_bytes(
                payload[offset:offset + 2],
                "big",
            )
            offset += 2 + cipher_suites_length

            # Compression methods
            if len(payload) < offset + 1:
                return None

            compression_length = payload[offset]
            offset += 1 + compression_length

            # Extensions length
            if len(payload) < offset + 2:
                return None

            extensions_length = int.from_bytes(
                payload[offset:offset + 2],
                "big",
            )
            offset += 2

            extensions_end = offset + extensions_length

            if len(payload) < extensions_end:
                return None

            # Search extensions for Server Name (SNI)
            while offset + 4 <= extensions_end:
                extension_type = int.from_bytes(
                    payload[offset:offset + 2],
                    "big",
                )

                extension_length = int.from_bytes(
                    payload[offset + 2:offset + 4],
                    "big",
                )

                offset += 4

                if offset + extension_length > extensions_end:
                    return None

                # server_name extension
                if extension_type == 0:
                    extension = payload[
                        offset:offset + extension_length
                    ]

                    if len(extension) < 5:
                        return None

                    server_name_list_length = int.from_bytes(
                        extension[0:2],
                        "big",
                    )

                    sni_offset = 2
                    sni_end = min(
                        2 + server_name_list_length,
                        len(extension),
                    )

                    while sni_offset + 3 <= sni_end:
                        name_type = extension[sni_offset]
                        name_length = int.from_bytes(
                            extension[
                                sni_offset + 1:
                                sni_offset + 3
                            ],
                            "big",
                        )

                        sni_offset += 3

                        if sni_offset + name_length > sni_end:
                            break

                        if name_type == 0:
                            hostname = extension[
                                sni_offset:
                                sni_offset + name_length
                            ].decode(
                                "utf-8",
                                errors="ignore",
                            ).lower().rstrip(".")

                            if hostname:
                                return hostname

                        sni_offset += name_length

                offset += extension_length

        except Exception:
            pass

        return None

    def _parse_quic_clienthello(
        self,
        payload: bytes,
    ) -> Optional[str]:
        try:
            if not payload:
                return None

            # QUIC long-header packet
            if not (payload[0] & 0x80):
                return None

            # A QUIC Initial packet carries an encrypted CRYPTO frame,
            # so the TLS ClientHello/SNI cannot be decoded directly here
            # without QUIC packet decryption keys.

            return None

        except Exception:
            return None
    # =========================================================
    # HOSTNAME MAPPING
    # =========================================================

    def _update_ip_hostname_mapping(
        self,
        ip_address: str,
        hostname: str,
    ) -> None:
        if not ip_address or not hostname:
            return

        hostname = hostname.lower().strip().rstrip(".")

        if not hostname or "." not in hostname:
            return

        now = datetime.now().timestamp()

        self.ip_hostname_mapping[ip_address] = {
            "hostname": hostname,
            "expiration_time": now + 1800,  # 30 minutes
        }

        # Update ALL previously captured packets
        for packet in self.captured_packets:
            if (
                packet.get("src_ip") == ip_address
                or packet.get("dst_ip") == ip_address
            ):
                packet["hostname"] = hostname

        # Update device recent packets
        for stats in self.device_stats.values():
            for packet in stats.get("recent_packets", []):
                if (
                    packet.get("src_ip") == ip_address
                    or packet.get("dst_ip") == ip_address
                ):
                    packet["hostname"] = hostname

    def _get_hostname_from_mapping(
        self,
        ip_address: str,
    ) -> Optional[str]:

        if not ip_address:
            return None

        mapping = self.ip_hostname_mapping.get(ip_address)

        if not mapping:
            return None

        if datetime.now().timestamp() > mapping.get(
            "expiration_time", 0
        ):
            self.ip_hostname_mapping.pop(ip_address, None)
            return None

        hostname = mapping.get("hostname")

        if hostname:
            return hostname.lower().rstrip(".")

        return None

    def _cleanup_expired_mappings(self) -> None:
        current_time = datetime.now().timestamp()

        expired = [
            ip
            for ip, mapping in self.ip_hostname_mapping.items()
            if current_time > mapping["expiration_time"]
        ]

        for ip in expired:
            del self.ip_hostname_mapping[ip]

    # =========================================================
    # DEVICE STATISTICS
    # =========================================================

    def _create_device_stats(
        self,
        ip: str,
        mac: Optional[str],
    ) -> Dict:
        return {
            "ip": ip,
            "mac": mac,
            "packet_count": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "protocols": {},
            "connections": set(),
            "last_activity": None,
            "threats": 0,
            "threat_score": 0,
            "severity": "SAFE",
            "recent_packets": [],
        }

    def _update_device_stats(
        self,
        packet_info: Dict,
    ) -> None:
        src_ip = packet_info.get("src_ip")
        dst_ip = packet_info.get("dst_ip")
        protocol = packet_info.get("protocol")
        size = packet_info.get("size", 0)
        timestamp = packet_info.get("timestamp")

        if src_ip:
            if src_ip not in self.device_stats:
                self.device_stats[src_ip] = self._create_device_stats(
                    src_ip,
                    packet_info.get("src_mac"),
                )

            stats = self.device_stats[src_ip]

            stats["packet_count"] += 1
            stats["bytes_sent"] += size
            stats["last_activity"] = timestamp

            if protocol:
                stats["protocols"][protocol] = (
                    stats["protocols"].get(protocol, 0) + 1
                )

            if dst_ip:
                stats["connections"].add(dst_ip)

            stats["recent_packets"].append({
                "timestamp": timestamp,
                "protocol": protocol,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "size": size,
                "hostname": packet_info.get("hostname"),
            })

            if len(stats["recent_packets"]) > self.max_device_packets:
                stats["recent_packets"].pop(0)

        if dst_ip:
            if dst_ip not in self.device_stats:
                self.device_stats[dst_ip] = self._create_device_stats(
                    dst_ip,
                    packet_info.get("dst_mac"),
                )

            stats = self.device_stats[dst_ip]

            stats["packet_count"] += 1
            stats["bytes_received"] += size
            stats["last_activity"] = timestamp

            if protocol:
                stats["protocols"][protocol] = (
                    stats["protocols"].get(protocol, 0) + 1
                )

            stats["recent_packets"].append({
                "timestamp": timestamp,
                "protocol": protocol,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "size": size,
                "hostname": packet_info.get("hostname"),
            })

            if len(stats["recent_packets"]) > self.max_device_packets:
                stats["recent_packets"].pop(0)

    # =========================================================
    # ARP THREAT DETECTION
    # =========================================================

    def _analyze_arp_packet(self, packet) -> None:
        if not packet.haslayer(ARP):
            return

        arp_packet = packet[ARP]

        if arp_packet.op != 2:
            return

        src_ip = arp_packet.psrc
        src_mac = arp_packet.hwsrc

        if not src_ip or not src_mac:
            return

        # Skip zero MAC addresses (invalid)
        if src_mac == "00:00:00:00:00:00":
            return

        if src_ip not in self.ip_mac_history:
            self.ip_mac_history[src_ip] = []

        if src_mac not in self.ip_mac_history[src_ip]:
            self.ip_mac_history[src_ip].append(src_mac)

        # Only detect gateway MAC changes after we've seen at least 3 ARP packets
        # to avoid false positives during network initialization
        if (src_ip.endswith(".1") or src_ip.endswith(".254")) and len(self.ip_mac_history.get(src_ip, [])) >= 3:
            if self.gateway_ip is None:
                self.gateway_ip = src_ip
                self.gateway_mac = src_mac

            elif self.gateway_mac != src_mac:
                # Add cooldown to prevent repeated alerts for the same gateway MAC change
                alert_key = f"gateway_mac_{src_ip}"
                current_time = time.time()
                
                if alert_key not in self.arp_spoof_alert_cooldown or current_time - self.arp_spoof_alert_cooldown[alert_key] > 60:
                    self._add_threat_event(
                        threat_type="arp_spoofing",
                        source_ip=src_ip,
                        source_mac=src_mac,
                        reason=(
                            f"Gateway MAC changed from "
                            f"{self.gateway_mac} to {src_mac}"
                        ),
                        severity="danger",
                    )
                    self.arp_spoof_alert_cooldown[alert_key] = current_time

                self.gateway_mac = src_mac

        # Only flag duplicate IP if we've seen more than 2 different MACs
        # and have collected at least 5 ARP packets for this IP
        if len(self.ip_mac_history[src_ip]) > 2 and len(self.ip_mac_history[src_ip]) >= 5:
            all_macs = ", ".join(
                self.ip_mac_history[src_ip]
            )

            self._add_threat_event(
                threat_type="duplicate_ip",
                source_ip=src_ip,
                source_mac=src_mac,
                reason=(
                    f"IP {src_ip} claimed by multiple "
                    f"MAC addresses: {all_macs}"
                ),
                severity="warn",
            )

        self.ip_mac_mapping[src_ip] = src_mac

    # =========================================================
    # THREAT EVENTS
    # =========================================================
    def _generate_ai_explanation(self, threat_data):
        import time

        prompt = f"""
    You are WiFi Guard's security explanation system.

    Give a VERY SHORT explanation of this detected threat.
    Maximum 2 sentences.

    Threat:
    {threat_data}
    """

        for attempt in range(3):
            try:
                response = gemini_client.models.generate_content(
                    model="gemini-3.6-flash",
                    contents=prompt
                )

                return response.text.strip()

            except Exception as e:
                print(f"[AI] Attempt {attempt + 1} failed: {e}")

                if attempt < 2:
                    time.sleep(2)

        return "AI explanation temporarily unavailable. Please try again."
        
    def _add_threat_event(
        self,
        threat_type: str,
        source_ip: Optional[str],
        source_mac: Optional[str],
        reason: str,
        severity: str,
        destination_ip: Optional[str] = None,
        risk_score: int = 0,
        hostname: Optional[str] = None,
        ) -> None:
        """
        Add a historical threat event and register it as active.
        """

        timestamp = datetime.now().isoformat()

        event = {
            "timestamp": timestamp,
            "threat_type": threat_type,
            "source_ip": source_ip,
            "source_mac": source_mac,
            "destination_ip": destination_ip,
            "hostname": hostname,
            "reason": reason,
            "severity": severity,
            "risk_score": risk_score,
            "active": True,
            "ai_explanation": "Analyzing threat...",
        }

        self.threat_events.append(event)

        if len(self.threat_events) > self.max_threat_events:
            self.threat_events.pop(0)

        threat_scores = {
            "suspicious_website": 10,
            "duplicate_ip": 40,
            "arp_spoofing": 80,
        }

        score = threat_scores.get(threat_type, 10)

        # Unique active threat key.
        threat_key = (
            f"{threat_type}:"
            f"{source_ip or ''}:"
            f"{destination_ip or ''}:"
            f"{reason}"
        )

        threat_data = {
            "timestamp": timestamp,
            "threat_type": threat_type,
            "source_ip": source_ip,
            "source_mac": source_mac,
            "destination_ip": destination_ip,
            "hostname": hostname,
            "reason": reason,
            "severity": severity,
            "score": score,
            "ai_explanation": "Analyzing threat..."
        }

        self.active_threats[threat_key] = threat_data

        
        self.total_threats += 1

        self._recalculate_active_threat_score()
        self._recalculate_device_threat_stats()

    def _recalculate_active_threat_score(self) -> None:
        if not self.active_threats:
            self.threat_score = 0
            self.severity = "SAFE"
            return

        self.threat_score = min(
            100,
            sum(
                threat.get("score", 10)
                for threat in self.active_threats.values()
            ),
        )

        if self.threat_score < 30:
            self.severity = "SAFE"
        elif self.threat_score < 70:
            self.severity = "WARNING"
        else:
            self.severity = "HIGH RISK"

    def _recalculate_device_threat_stats(self) -> None:
        # Reset active threat state for every device.
        for stats in self.device_stats.values():
            stats["threats"] = 0
            stats["threat_score"] = 0
            stats["severity"] = "SAFE"

        # Rebuild from active threats.
        for threat in self.active_threats.values():
            source_ip = threat.get("source_ip")

            if not source_ip:
                continue

            if source_ip not in self.device_stats:
                continue

            stats = self.device_stats[source_ip]

            stats["threats"] += 1
            stats["threat_score"] = min(
                100,
                stats["threat_score"]
                + threat.get("score", 10),
            )

            if stats["threat_score"] < 30:
                stats["severity"] = "SAFE"
            elif stats["threat_score"] < 70:
                stats["severity"] = "WARNING"
            else:
                stats["severity"] = "HIGH RISK"

    def clear_suspicious_domain(
        self,
        domain: Optional[str] = None,
        destination_ip: Optional[str] = None,
    ) -> None:
        """
        Clear an active suspicious website threat after unblock.
        Historical event remains in threat_events.
        """

        domain_normalized = (
            domain.lower().rstrip(".")
            if domain
            else None
        )

        keys_to_remove = []

        for key, threat in self.active_threats.items():
            if threat.get("threat_type") != "suspicious_website":
                continue

            threat_domain = None

            reason = threat.get("reason", "")

            if ": " in reason:
                threat_domain = (
                    reason.split(": ", 1)[1]
                    .lower()
                    .rstrip(".")
                )

            matches_domain = (
                domain_normalized
                and threat_domain == domain_normalized
            )

            matches_ip = (
                destination_ip
                and threat.get("destination_ip")
                == destination_ip
            )

            if matches_domain or matches_ip:
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self.active_threats[key]

        # Allow the same domain to alert again later.
        if domain_normalized:
            self.suspicious_domain_alerted.discard(
                domain_normalized
            )

            

        if destination_ip:
            self.blocked_destinations.discard(
                destination_ip
            )

        # Mark matching historical events inactive.
        for event in self.threat_events:
            if event.get("threat_type") != "suspicious_website":
                continue

            event_domain = None
            reason = event.get("reason", "")

            if ": " in reason:
                event_domain = (
                    reason.split(": ", 1)[1]
                    .lower()
                    .rstrip(".")
                )

            if (
                (
                    domain_normalized
                    and event_domain == domain_normalized
                )
                or (
                    destination_ip
                    and event.get("destination_ip")
                    == destination_ip
                )
            ):
                event["active"] = False

        self._recalculate_active_threat_score()
        self._recalculate_device_threat_stats()


    # =========================================================
    # MONITORING
    # =========================================================

    def start_monitoring(
        self,
        interface: Optional[str] = None,
    ) -> Dict:
        if self.monitoring:
            return {
                "success": False,
                "message": "Monitoring is already active",
                "monitoring": True,
            }

        target_interface = interface or self.interface

        try:
            self.monitoring = True
            self.stop_event.clear()

            self.packet_count = 0
            self.captured_packets = []
            self.error_message = None
            self.start_time = datetime.now()

            # Reset ARP state.
            self.gateway_mac = None
            self.gateway_ip = None
            self.ip_mac_mapping = {}
            self.ip_mac_history = {}

            # Reset current-session threats.
            self.threat_events = []
            self.active_threats = {}
            self.suspicious_domain_alerted = set()

            self.threat_score = 0
            self.severity = "SAFE"
            self.total_threats = 0

            # Reset device statistics.
            self.device_stats = {}

            # Reset hostname state.
            self.ip_hostname_mapping = {}
            self.dns_request_clients = {}

            # Keep firewall blocked destinations intact.
            

            self.monitor_thread = threading.Thread(
                target=self._monitor_loop,
                args=(target_interface,),
                daemon=True,
            )

            self.monitor_thread.start()

            return {
                "success": True,
                "message": (
                    "Packet monitoring started on interface: "
                    f"{target_interface or 'auto-detect'}"
                ),
                "monitoring": True,
                "interface": target_interface,
                "start_time": self.start_time.isoformat(),
            }

        except PermissionError as e:
            self.monitoring = False
            self.error_message = (
                f"Permission denied: {str(e)}. "
                "Administrator privileges required."
            )

            return {
                "success": False,
                "message": self.error_message,
                "monitoring": False,
                "error": "permission_denied",
            }

        except Scapy_Exception as e:
            self.monitoring = False
            self.error_message = f"Scapy error: {str(e)}"

            return {
                "success": False,
                "message": self.error_message,
                "monitoring": False,
                "error": "scapy_error",
            }

        except Exception as e:
            self.monitoring = False
            self.error_message = f"Unexpected error: {str(e)}"

            return {
                "success": False,
                "message": self.error_message,
                "monitoring": False,
                "error": "unknown_error",
            }

    def _monitor_loop(
        self,
        interface: Optional[str],
    ) -> None:
        try:
            sniff(
                prn=self._packet_handler,
                stop_filter=lambda p: self.stop_event.is_set(),
                store=False,
                iface=interface,
            )

        except PermissionError as e:
            self.error_message = (
                f"Permission denied: {str(e)}. "
                "Administrator privileges required."
            )
            self.monitoring = False

        except Scapy_Exception as e:
            self.error_message = f"Scapy error: {str(e)}"
            self.monitoring = False

        except Exception as e:
            self.error_message = f"Monitoring error: {str(e)}"
            self.monitoring = False

    def stop_monitoring(self) -> Dict:
        if not self.monitoring:
            return {
                "success": False,
                "message": "Monitoring is not active",
                "monitoring": False,
            }

        try:
            self.stop_event.set()
            self.monitoring = False

            if (
                self.monitor_thread
                and self.monitor_thread.is_alive()
            ):
                self.monitor_thread.join(timeout=5)

            end_time = datetime.now()

            duration = (
                (end_time - self.start_time).total_seconds()
                if self.start_time
                else 0
            )

            return {
                "success": True,
                "message": "Packet monitoring stopped",
                "monitoring": False,
                "packet_count": self.packet_count,
                "duration_seconds": round(duration, 2),
                "end_time": end_time.isoformat(),
            }

        except Exception as e:
            return {
                "success": False,
                "message": f"Error stopping monitoring: {str(e)}",
                "monitoring": False,
                "error": "stop_error",
            }

    # =========================================================
    # API DATA
    # =========================================================

    def get_status(self) -> Dict:
        duration = 0

        if self.monitoring and self.start_time:
            duration = (
                datetime.now() - self.start_time
            ).total_seconds()

        return {
            "monitoring": self.monitoring,
            "packet_count": self.packet_count,
            "captured_packets_count": len(
                self.captured_packets
            ),
            "threat_events_count": len(
                self.threat_events
            ),
            "active_threats_count": len(
                self.active_threats
            ),
            "threat_score": self.threat_score,
            "severity": self.severity,
            "total_threats": self.total_threats,
            "interface": self.interface,
            "start_time": (
                self.start_time.isoformat()
                if self.start_time
                else None
            ),
            "duration_seconds": round(duration, 2),
            "error_message": self.error_message,
        }

    def get_threat_events(
        self,
        limit: Optional[int] = None,
    ) -> List[Dict]:
        """
        Return newest threat events first.
        """

        events = list(reversed(self.threat_events))

        if limit:
            return events[:limit]

        return events

    def get_device_stats(
        self,
        ip_address: Optional[str] = None,
    ) -> Dict:

        if ip_address:
            if ip_address not in self.device_stats:
                return {
                    "ip": ip_address,
                    "found": False,
                }

            stats = self.device_stats[ip_address]

            return {
                "ip": stats["ip"],
                "mac": stats["mac"],
                "packet_count": stats["packet_count"],
                "bytes_sent": stats["bytes_sent"],
                "bytes_received": stats["bytes_received"],
                "protocols": stats["protocols"],
                "connections": list(
                    stats["connections"]
                ),
                "connection_count": len(
                    stats["connections"]
                ),
                "last_activity": stats["last_activity"],
                "threats": stats["threats"],
                "threat_score": stats.get(
                    "threat_score",
                    0,
                ),
                "severity": stats.get(
                    "severity",
                    "SAFE",
                ),
                "recent_packets": stats.get(
                    "recent_packets",
                    [],
                ),
            }

        devices = []

        for stats in self.device_stats.values():
            devices.append({
                "ip": stats["ip"],
                "mac": stats["mac"],
                "packet_count": stats["packet_count"],
                "bytes_sent": stats["bytes_sent"],
                "bytes_received": stats["bytes_received"],
                "protocols": stats["protocols"],
                "connections": list(
                    stats["connections"]
                ),
                "connection_count": len(
                    stats["connections"]
                ),
                "last_activity": stats["last_activity"],
                "threats": stats["threats"],
                "threat_score": stats.get(
                    "threat_score",
                    0,
                ),
                "severity": stats.get(
                    "severity",
                    "SAFE",
                ),
            })

        return {
            "devices": devices,
            "count": len(devices),
        }

    def get_captured_packets(
        self,
        limit: Optional[int] = None,
    ) -> List[Dict]:

        if limit:
            return list(
                reversed(
                    self.captured_packets[-limit:]
                )
            )

        return list(
            reversed(self.captured_packets)
        )
