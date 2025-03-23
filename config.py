DETECTION_RULES = {
    'directory_bruteforce': {
        'pattern': r'/(admin|wp-admin|login|administrator|wp-login|phpmyadmin)\b',
        'threshold': 5,
        'timeframe': 300,
        'severity': 'medium'
    },
    'cve_exploit': {
        'pattern': r'CVE-\d{4}-\d+',
        'threshold': 1,
        'severity': 'high'
    },
    'sql_injection': {
        'pattern': r'(?i)(union\s+select|drop\s+table|--|\%27|\'|\%22|\b(sleep|benchmark|wait)\b.*?\d+)',
        'threshold': 1,
        'severity': 'high'
    },
    'xss_attempt': {
        'pattern': r'(?i)(<script|javascript:|alert\(|onerror\s*=|onload\s*=|eval\(|\bon\w+\s*=)',
        'threshold': 1,
        'severity': 'high'
    },
    'path_traversal': {
        'pattern': r'(?:\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f)',
        'threshold': 1,
        'severity': 'high'
    },
    'command_injection': {
        'pattern': r'(?i)(`|\$\(|system\(|exec\(|\||\&\&|\b(ping|wget|curl|bash|sh|nc|netcat)\b)',
        'threshold': 1,
        'severity': 'critical'
    },
    'file_inclusion': {
        'pattern': r'(?i)(include|require|include_once|require_once).*(http|ftp|php|zlib|data|glob|phar|ssh2|rar|ogg|expect)',
        'threshold': 1,
        'severity': 'critical'
    },
    'scanner_detection': {
        'pattern': r'(?i)(nmap|nikto|sqlmap|acunetix|burpsuite|w3af|nessus|openvas|wpscan|dirbuster)',
        'threshold': 1,
        'severity': 'medium'
    }
}