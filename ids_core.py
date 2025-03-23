import json
import os
from datetime import datetime
import re
import ipaddress

# Define regular expressions for common attack patterns
ATTACK_PATTERNS = {
    "xss": re.compile(r'<script>|<\/script>|alert\s*\(|on\w+\s*=|javascript:|iframe\s|<img\s+src=[^>]*onerror=',
                      re.IGNORECASE),
    "sql": re.compile(
        r'(?:\b(?:select|union|insert|update|delete|drop|alter)\b.*\b(?:from|into|where|table|database)\b)|(?:--[^\r\n]*)|(?:\/\*(?:.|[\r\n])*?\*\/)|(?:;\s*$)',
        re.IGNORECASE),
    "path_traversal": re.compile(r'\.{2}[\/\\]|%2e%2e%2f|%252e%252e%252f', re.IGNORECASE),
    "command_injection": re.compile(r'[$;|`]|\b(?:cat|echo|rm|chmod|chown|wget|curl|nc|bash|sh|python)\b',
                                    re.IGNORECASE),
    "lfi": re.compile(r'(?:\.\.|%2e%2e)(?:\/|%2f)(?:etc|proc|var|config|windows)', re.IGNORECASE),
}

# Known bad IP addresses (example)
BAD_IP_RANGES = [
    "192.168.200.0/24",  # Example bad IP range
    "10.0.100.0/24",  # Example bad IP range
]

# Convert IP ranges to network objects
BAD_NETWORKS = [ipaddress.ip_network(cidr) for cidr in BAD_IP_RANGES]


class IDSCore:
    def __init__(self, log_file="backend/logs/ids.log"):
        """Initialize IDS core with log file path."""
        self.log_file = log_file
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

    def detect_attack(self, data, ip):
        """
        Analyze data for potential attacks.

        Args:
            data (str): The data to analyze
            ip (str): The source IP address

        Returns:
            tuple: (is_attack, attack_type, severity)
        """
        # Check for known bad IPs
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in BAD_NETWORKS:
                if ip_obj in network:
                    return True, "MALICIOUS_IP", "High"
        except ValueError:
            # Invalid IP, could be suspicious
            pass

        # Check data against attack patterns
        if not data:
            return False, None, None

        data_str = str(data)

        for attack_type, pattern in ATTACK_PATTERNS.items():
            if pattern.search(data_str):
                # Determine severity based on attack type
                severity = "Medium"  # Default
                if attack_type in ["sql", "command_injection"]:
                    severity = "High"
                elif attack_type in ["xss"]:
                    severity = "Low"

                return True, attack_type.upper(), severity

        # No attack detected
        return False, None, None

    def log_attack(self, attack_data):
        """Log attack data to file."""
        try:
            # Ensure timestamp is included
            if "timestamp" not in attack_data:
                attack_data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            with open(self.log_file, "a") as file:
                file.write(json.dumps(attack_data) + "\n")
            return True
        except Exception as e:
            print(f"Error writing to log file: {e}")
            return False

    def get_logs(self):
        """Read and return all logs."""
        logs = []
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, "r") as file:
                    logs = [json.loads(line.strip()) for line in file if line.strip()]
        except Exception as e:
            print(f"Error reading log file: {e}")
        return logs

    def analyze_request(self, request_data, source_ip):
        """
        Analyze an HTTP request for potential attacks.

        Args:
            request_data (dict): Request data (headers, params, body, etc.)
            source_ip (str): Source IP address

        Returns:
            dict: Attack information if detected, None otherwise
        """
        # Check IP first
        is_ip_attack, attack_type, severity = self.check_ip(source_ip)
        if is_ip_attack:
            return {
                "type": attack_type,
                "severity": severity,
                "description": "Suspicious IP address detected",
                "ip": source_ip
            }

        # Check URL parameters
        if "params" in request_data:
            is_attack, attack_type, severity = self.detect_attack(request_data["params"], source_ip)
            if is_attack:
                return {
                    "type": attack_type,
                    "severity": severity,
                    "description": "Attack pattern detected in URL parameters",
                    "ip": source_ip
                }

        # Check request body
        if "body" in request_data:
            is_attack, attack_type, severity = self.detect_attack(request_data["body"], source_ip)
            if is_attack:
                return {
                    "type": attack_type,
                    "severity": severity,
                    "description": "Attack pattern detected in request body",
                    "ip": source_ip
                }

        # Check headers
        if "headers" in request_data:
            is_attack, attack_type, severity = self.detect_attack(json.dumps(request_data["headers"]), source_ip)
            if is_attack:
                return {
                    "type": attack_type,
                    "severity": severity,
                    "description": "Attack pattern detected in HTTP headers",
                    "ip": source_ip
                }

        # No attack detected
        return None

    def check_ip(self, ip):
        """Check if an IP is in the known bad ranges."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in BAD_NETWORKS:
                if ip_obj in network:
                    return True, "MALICIOUS_IP", "High"
        except ValueError:
            # Invalid IP format
            return False, None, None

        # Rate limiting check could go here

        return False, None, None

    def generate_sample_attacks(self, count=10):
        """Generate sample attack logs for testing."""
        import random

        attack_types = ["XSS", "SQL", "DDOS", "BRUTEFORCE", "MITM", "PATH_TRAVERSAL", "COMMAND_INJECTION"]
        severities = {
            "XSS": "Low",
            "SQL": "High",
            "DDOS": "High",
            "BRUTEFORCE": "Medium",
            "MITM": "Medium",
            "PATH_TRAVERSAL": "Medium",
            "COMMAND_INJECTION": "High"
        }
        descriptions = {
            "XSS": "Cross-site Scripting",
            "SQL": "Database Attack",
            "DDOS": "Denial of Service",
            "BRUTEFORCE": "Password Attack",
            "MITM": "Man in the Middle",
            "PATH_TRAVERSAL": "Directory Traversal",
            "COMMAND_INJECTION": "OS Command Injection"
        }

        # Generate random IPs
        ips = [f"192.168.1.{random.randint(1, 254)}" for _ in range(min(count, 20))]

        logs = []
        for _ in range(count):
            attack_type = random.choice(attack_types)
            timestamp = (datetime.now().timestamp() - random.randint(0, 86400)) * 1000  # Random time in last 24h

            attack_data = {
                "timestamp": datetime.fromtimestamp(timestamp / 1000).strftime("%Y-%m-%d %H:%M:%S"),
                "type": attack_type,
                "severity": severities.get(attack_type, "Medium"),
                "description": descriptions.get(attack_type, "Unknown Attack"),
                "ip": random.choice(ips),
                "details": f"Sample {attack_type} attack generated for testing"
            }

            self.log_attack(attack_data)
            logs.append(attack_data)

        return logs