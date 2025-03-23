import json
from datetime import datetime
import os


class AttackLogger:
    def __init__(self, log_file="backend/logs/attacks.log", blocked_file="backend/logs/blocked_ips.json"):
        """Initialize the attack logger with file paths."""
        self.log_file = log_file
        self.blocked_file = blocked_file

        # Ensure directories exist
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        os.makedirs(os.path.dirname(blocked_file), exist_ok=True)

        # Initialize blocked IPs file if it doesn't exist
        if not os.path.exists(blocked_file):
            with open(blocked_file, 'w') as f:
                json.dump({
                    "blocked_ips": [],
                    "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }, f)

    def log_attack(self, attack_data):
        """Log attack to the attacks log file."""
        # Ensure timestamp exists
        if "timestamp" not in attack_data:
            attack_data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open(self.log_file, 'a') as f:
            f.write(json.dumps(attack_data) + '\n')

        # Check if we should block this IP based on rules
        self._check_for_block(attack_data)

        return True

    def _check_for_block(self, attack_data):
        """Check if the IP address should be blocked based on attack patterns."""
        ip = attack_data.get("ip")
        if not ip:
            return False

        # Load current blocked IPs
        blocked_data = self._load_blocked_ips()

        # Skip if already blocked
        if ip in blocked_data["blocked_ips"]:
            return True

        # Implement blocking rules
        # For example, block if:
        # 1. It's a high severity attack
        # 2. It's a specific attack type we want to block
        severity = attack_data.get("severity", "").lower()
        attack_type = attack_data.get("type", "").lower()

        should_block = False

        # High severity attacks are auto-blocked
        if severity == "high":
            should_block = True

        # Block SQL injection attempts
        if "sql" in attack_type:
            should_block = True

        # Block command injection attempts    
        if "command" in attack_type or "injection" in attack_type:
            should_block = True

        if should_block:
            return self.block_ip(ip)

        return False

    def block_ip(self, ip):
        """Add an IP to the blocked list."""
        blocked_data = self._load_blocked_ips()

        # Skip if already blocked
        if ip in blocked_data["blocked_ips"]:
            return True

        # Add to blocked list
        blocked_data["blocked_ips"].append(ip)
        blocked_data["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Save updated list
        with open(self.blocked_file, 'w') as f:
            json.dump(blocked_data, f, indent=2)

        return True

    def unblock_ip(self, ip):
        """Remove an IP from the blocked list."""
        blocked_data = self._load_blocked_ips()

        if ip in blocked_data["blocked_ips"]:
            blocked_data["blocked_ips"].remove(ip)
            blocked_data["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            with open(self.blocked_file, 'w') as f:
                json.dump(blocked_data, f, indent=2)

            return True
        return False

    def _load_blocked_ips(self):
        """Load the list of blocked IPs."""
        try:
            with open(self.blocked_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            # If file doesn't exist or is corrupt, create a new one
            default_data = {
                "blocked_ips": [],
                "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            with open(self.blocked_file, 'w') as f:
                json.dump(default_data, f)
            return default_data

    def get_blocked_ips(self):
        """Return the list of currently blocked IP addresses."""
        blocked_data = self._load_blocked_ips()
        return blocked_data["blocked_ips"]

    def is_ip_blocked(self, ip):
        """Check if a specific IP is currently blocked."""
        blocked_ips = self.get_blocked_ips()
        return ip in blocked_ips