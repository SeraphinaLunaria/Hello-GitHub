# Python Guide for Cybersecurity Students

Welcome to the comprehensive Python guide designed specifically for cybersecurity beginners! This guide will help you build a strong foundation in Python programming while focusing on defensive security concepts.

## Table of Contents
1. [Introduction](#introduction)
2. [Environment Setup](#environment-setup)
3. [Python Basics for Security](#python-basics-for-security)
4. [Essential Security Libraries](#essential-security-libraries)
5. [Network Security Basics](#network-security-basics)
6. [Cryptography Fundamentals](#cryptography-fundamentals)
7. [Log Analysis and Parsing](#log-analysis-and-parsing)
8. [Web Security Basics](#web-security-basics)
9. [Practical Exercises](#practical-exercises)
10. [Additional Resources](#additional-resources)

---

## Introduction

Python is one of the most popular programming languages in cybersecurity due to its:
- **Simplicity**: Easy to learn and read
- **Rich ecosystem**: Thousands of security-focused libraries
- **Versatility**: Used for scripting, automation, analysis, and tool development
- **Community**: Large security community with excellent resources

### What You'll Learn
- Python fundamentals with a security focus
- How to write defensive security tools
- Network analysis and monitoring
- Log parsing and analysis
- Cryptographic implementations
- Security automation

---

## Environment Setup

### Installing Python

**Linux/Mac:**
```bash
# Check if Python is installed
python3 --version

# Install Python (Ubuntu/Debian)
sudo apt update
sudo apt install python3 python3-pip python3-venv

# Install Python (Mac with Homebrew)
brew install python3
```

**Windows:**
1. Download from [python.org](https://www.python.org/downloads/)
2. Run installer and check "Add Python to PATH"
3. Verify installation: `python --version`

### Setting Up Virtual Environment

```bash
# Create a virtual environment
python3 -m venv cybersec_env

# Activate it
# Linux/Mac:
source cybersec_env/bin/activate

# Windows:
cybersec_env\Scripts\activate

# Install security packages
pip install scapy cryptography requests pycryptodome
```

---

## Python Basics for Security

### 1. Variables and Data Types

```python
# String - for usernames, passwords, IP addresses
ip_address = "192.168.1.1"
username = "admin"

# Integer - for ports, counters
port = 443
failed_attempts = 0

# Lists - for collections of IPs, users, logs
blocked_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
allowed_ports = [80, 443, 8080]

# Dictionaries - for structured data
user_data = {
    "username": "alice",
    "role": "admin",
    "last_login": "2025-10-28",
    "failed_attempts": 0
}
```

### 2. Control Flow

```python
# If statements - for security checks
def check_access(user_role):
    if user_role == "admin":
        print("Full access granted")
    elif user_role == "user":
        print("Limited access granted")
    else:
        print("Access denied")

# Loops - for processing logs or scanning
suspicious_ips = ["10.0.0.5", "10.0.0.7"]

for ip in suspicious_ips:
    print(f"Investigating IP: {ip}")
```

### 3. Functions

```python
def validate_password(password):
    """
    Check if password meets security requirements
    """
    if len(password) < 8:
        return False, "Password too short"

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*" for c in password)

    if not (has_upper and has_lower and has_digit and has_special):
        return False, "Password must contain uppercase, lowercase, digit, and special character"

    return True, "Password is strong"

# Test the function
result, message = validate_password("Secure123!")
print(f"Valid: {result}, Message: {message}")
```

### 4. File Handling

```python
# Reading log files
def analyze_log_file(filename):
    failed_logins = []

    try:
        with open(filename, 'r') as file:
            for line in file:
                if "Failed password" in line:
                    failed_logins.append(line.strip())

        return failed_logins
    except FileNotFoundError:
        print(f"File {filename} not found")
        return []

# Writing security reports
def write_security_report(findings, output_file):
    with open(output_file, 'w') as file:
        file.write("=== Security Analysis Report ===\n")
        file.write(f"Generated: {datetime.now()}\n\n")

        for finding in findings:
            file.write(f"- {finding}\n")
```

---

## Essential Security Libraries

### 1. Hashlib - For Hashing

```python
import hashlib

def hash_password(password):
    """
    Create a SHA-256 hash of a password
    Note: In production, use bcrypt or argon2!
    """
    return hashlib.sha256(password.encode()).hexdigest()

# Example
password = "MySecurePassword123"
hashed = hash_password(password)
print(f"Original: {password}")
print(f"Hashed: {hashed}")

# Verify file integrity
def calculate_file_hash(filename):
    """
    Calculate SHA-256 hash of a file for integrity checking
    """
    sha256_hash = hashlib.sha256()

    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest()
```

### 2. Cryptography - For Encryption

```python
from cryptography.fernet import Fernet

def encrypt_message(message):
    """
    Encrypt a message using Fernet (symmetric encryption)
    """
    # Generate key (store this securely!)
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)

    # Encrypt
    encrypted_text = cipher_suite.encrypt(message.encode())

    return key, encrypted_text

def decrypt_message(key, encrypted_text):
    """
    Decrypt a message using the key
    """
    cipher_suite = Fernet(key)
    decrypted_text = cipher_suite.decrypt(encrypted_text)

    return decrypted_text.decode()

# Example
message = "Sensitive data: User credentials"
key, encrypted = encrypt_message(message)
decrypted = decrypt_message(key, encrypted)

print(f"Original: {message}")
print(f"Encrypted: {encrypted}")
print(f"Decrypted: {decrypted}")
```

### 3. Requests - For Web Security

```python
import requests

def check_ssl_certificate(url):
    """
    Check if a website has valid SSL certificate
    """
    try:
        response = requests.get(url, timeout=5)

        if response.url.startswith('https://'):
            print(f"✓ {url} uses HTTPS")
            print(f"Status Code: {response.status_code}")
            return True
        else:
            print(f"✗ {url} does not use HTTPS")
            return False

    except requests.exceptions.SSLError:
        print(f"✗ SSL Certificate Error for {url}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"✗ Error: {e}")
        return False

# Example
check_ssl_certificate("https://example.com")
```

---

## Network Security Basics

### 1. IP Address Validation

```python
import ipaddress

def validate_ip(ip_string):
    """
    Validate if string is a valid IP address
    """
    try:
        ip = ipaddress.ip_address(ip_string)

        if ip.is_private:
            return f"Valid private IP: {ip}"
        elif ip.is_loopback:
            return f"Valid loopback IP: {ip}"
        elif ip.is_global:
            return f"Valid public IP: {ip}"
        else:
            return f"Valid IP: {ip}"

    except ValueError:
        return f"Invalid IP address: {ip_string}"

# Test
print(validate_ip("192.168.1.1"))
print(validate_ip("8.8.8.8"))
print(validate_ip("invalid"))
```

### 2. Port Scanner (Educational)

```python
import socket
from datetime import datetime

def scan_port(host, port):
    """
    Check if a specific port is open
    Note: Only scan systems you own or have permission to test!
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()

        return result == 0  # True if port is open
    except socket.error:
        return False

def scan_common_ports(host):
    """
    Scan common ports on a host
    WARNING: Only use on systems you own!
    """
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        5432: "PostgreSQL",
        8080: "HTTP-Alt"
    }

    print(f"\n[*] Starting scan on {host} at {datetime.now()}")
    print("-" * 50)

    open_ports = []

    for port, service in common_ports.items():
        if scan_port(host, port):
            print(f"[+] Port {port:5d} - {service:15s} - OPEN")
            open_ports.append((port, service))
        else:
            print(f"[-] Port {port:5d} - {service:15s} - Closed")

    print("-" * 50)
    print(f"[*] Scan completed. Found {len(open_ports)} open ports")

    return open_ports

# Example (only use on localhost or systems you own!)
# scan_common_ports("127.0.0.1")
```

### 3. Network Request Analysis

```python
def analyze_url(url):
    """
    Extract and analyze components of a URL for security
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)

    print(f"URL Analysis:")
    print(f"  Scheme: {parsed.scheme}")
    print(f"  Domain: {parsed.netloc}")
    print(f"  Path: {parsed.path}")
    print(f"  Parameters: {parsed.params}")
    print(f"  Query: {parsed.query}")

    # Security checks
    if parsed.scheme != "https":
        print("  ⚠️ Warning: Not using HTTPS")

    if ".." in parsed.path:
        print("  ⚠️ Warning: Potential directory traversal")

    return parsed

# Example
analyze_url("https://example.com/api/users?id=123")
```

---

## Cryptography Fundamentals

### 1. Password Hashing (Proper Method)

```python
import bcrypt

def hash_password_secure(password):
    """
    Hash password using bcrypt (industry standard)
    """
    # Generate salt and hash password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

def verify_password(password, hashed):
    """
    Verify password against hash
    """
    return bcrypt.checkpw(password.encode(), hashed)

# Example (install bcrypt: pip install bcrypt)
# password = "SuperSecret123!"
# hashed = hash_password_secure(password)
# print(f"Hashed: {hashed}")
# print(f"Verify correct: {verify_password('SuperSecret123!', hashed)}")
# print(f"Verify wrong: {verify_password('WrongPassword', hashed)}")
```

### 2. Data Encryption/Decryption

```python
from cryptography.fernet import Fernet
import base64

class SecureDataHandler:
    """
    Handle encryption and decryption of sensitive data
    """

    def __init__(self):
        self.key = None

    def generate_key(self):
        """Generate and store encryption key"""
        self.key = Fernet.generate_key()
        return self.key

    def save_key(self, filename="secret.key"):
        """Save key to file"""
        with open(filename, "wb") as key_file:
            key_file.write(self.key)

    def load_key(self, filename="secret.key"):
        """Load key from file"""
        with open(filename, "rb") as key_file:
            self.key = key_file.read()

    def encrypt_data(self, data):
        """Encrypt data"""
        if not self.key:
            raise ValueError("No key loaded")

        f = Fernet(self.key)
        encrypted = f.encrypt(data.encode())
        return encrypted

    def decrypt_data(self, encrypted_data):
        """Decrypt data"""
        if not self.key:
            raise ValueError("No key loaded")

        f = Fernet(self.key)
        decrypted = f.decrypt(encrypted_data)
        return decrypted.decode()

# Example usage
handler = SecureDataHandler()
handler.generate_key()

secret_message = "Database password: admin123"
encrypted = handler.encrypt_data(secret_message)
decrypted = handler.decrypt_data(encrypted)

print(f"Original: {secret_message}")
print(f"Encrypted: {encrypted}")
print(f"Decrypted: {decrypted}")
```

---

## Log Analysis and Parsing

### 1. Basic Log Parser

```python
import re
from collections import Counter
from datetime import datetime

def parse_auth_log(log_file):
    """
    Parse authentication logs and extract security events
    """
    failed_attempts = Counter()
    successful_logins = []
    suspicious_activities = []

    # Pattern for failed SSH attempts
    failed_pattern = r'Failed password for (\w+) from ([\d.]+)'
    success_pattern = r'Accepted password for (\w+) from ([\d.]+)'

    try:
        with open(log_file, 'r') as f:
            for line in f:
                # Check for failed attempts
                failed_match = re.search(failed_pattern, line)
                if failed_match:
                    username, ip = failed_match.groups()
                    failed_attempts[ip] += 1

                    # Flag suspicious activity (multiple failures)
                    if failed_attempts[ip] > 5:
                        suspicious_activities.append(
                            f"Multiple failed attempts from {ip} (Count: {failed_attempts[ip]})"
                        )

                # Check for successful logins
                success_match = re.search(success_pattern, line)
                if success_match:
                    username, ip = success_match.groups()
                    successful_logins.append((username, ip))

        return {
            'failed_attempts': dict(failed_attempts),
            'successful_logins': successful_logins,
            'suspicious': suspicious_activities
        }

    except FileNotFoundError:
        print(f"Log file {log_file} not found")
        return None

def generate_security_report(analysis):
    """
    Generate a readable security report
    """
    print("\n" + "="*60)
    print("SECURITY LOG ANALYSIS REPORT")
    print("="*60)

    print(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    print("\n--- Failed Login Attempts ---")
    if analysis['failed_attempts']:
        for ip, count in sorted(analysis['failed_attempts'].items(),
                                key=lambda x: x[1], reverse=True):
            print(f"  IP: {ip:15s} - {count} attempts")
    else:
        print("  No failed attempts detected")

    print("\n--- Successful Logins ---")
    if analysis['successful_logins']:
        for username, ip in analysis['successful_logins'][:10]:
            print(f"  User: {username:10s} from {ip}")
    else:
        print("  No successful logins detected")

    print("\n--- Suspicious Activities ---")
    if analysis['suspicious']:
        for activity in analysis['suspicious']:
            print(f"  ⚠️ {activity}")
    else:
        print("  ✓ No suspicious activities detected")

    print("\n" + "="*60)

# Example usage
# analysis = parse_auth_log('/var/log/auth.log')
# if analysis:
#     generate_security_report(analysis)
```

### 2. Web Server Log Analysis

```python
def parse_apache_log(log_line):
    """
    Parse Apache/Nginx access log line
    """
    # Pattern for common log format
    pattern = r'(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) \S+" (\d+) (\d+)'
    match = re.match(pattern, log_line)

    if match:
        ip, timestamp, method, path, status, size = match.groups()
        return {
            'ip': ip,
            'timestamp': timestamp,
            'method': method,
            'path': path,
            'status': int(status),
            'size': int(size)
        }
    return None

def detect_web_attacks(log_file):
    """
    Detect potential web attacks in logs
    """
    attacks = {
        'sql_injection': [],
        'xss': [],
        'directory_traversal': [],
        'brute_force': Counter()
    }

    # Attack patterns
    sql_patterns = [r"union.*select", r"or.*1=1", r"exec.*xp_"]
    xss_patterns = [r"<script>", r"javascript:", r"onerror="]
    traversal_patterns = [r"\.\./", r"\.\.\\"]

    try:
        with open(log_file, 'r') as f:
            for line in f:
                entry = parse_apache_log(line)
                if not entry:
                    continue

                path = entry['path'].lower()

                # Check for SQL injection
                if any(re.search(p, path, re.IGNORECASE) for p in sql_patterns):
                    attacks['sql_injection'].append(entry)

                # Check for XSS
                if any(re.search(p, path, re.IGNORECASE) for p in xss_patterns):
                    attacks['xss'].append(entry)

                # Check for directory traversal
                if any(re.search(p, path) for p in traversal_patterns):
                    attacks['directory_traversal'].append(entry)

                # Track failed login attempts (401/403)
                if entry['status'] in [401, 403]:
                    attacks['brute_force'][entry['ip']] += 1

        return attacks

    except FileNotFoundError:
        print(f"Log file {log_file} not found")
        return None
```

---

## Web Security Basics

### 1. Input Validation

```python
import re

def validate_email(email):
    """
    Validate email address format
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def sanitize_input(user_input):
    """
    Remove potentially dangerous characters
    """
    # Remove special characters that could be used in attacks
    dangerous_chars = ['<', '>', '"', "'", '/', '\\', ';', '&', '|']

    sanitized = user_input
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')

    return sanitized

def validate_username(username):
    """
    Validate username (alphanumeric and underscore only)
    """
    pattern = r'^[a-zA-Z0-9_]{3,20}$'

    if not re.match(pattern, username):
        return False, "Username must be 3-20 characters (letters, numbers, underscore only)"

    return True, "Valid username"

# Examples
print(validate_email("user@example.com"))  # True
print(validate_email("invalid.email"))      # False

print(sanitize_input("Hello<script>alert('xss')</script>"))
# Output: "Helloalert('xss')script"

print(validate_username("user_123"))  # True, "Valid username"
print(validate_username("us"))        # False, "Username must be..."
```

### 2. Security Headers Checker

```python
import requests

def check_security_headers(url):
    """
    Check if website implements important security headers
    """
    important_headers = {
        'Strict-Transport-Security': 'HSTS - Forces HTTPS',
        'X-Content-Type-Options': 'Prevents MIME sniffing',
        'X-Frame-Options': 'Prevents clickjacking',
        'X-XSS-Protection': 'XSS filter',
        'Content-Security-Policy': 'Prevents XSS and injection',
        'Referrer-Policy': 'Controls referrer information'
    }

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        print(f"\n[*] Security Headers Analysis for {url}")
        print("="*60)

        for header, description in important_headers.items():
            if header in headers:
                print(f"✓ {header:30s} - Present")
                print(f"  Value: {headers[header]}")
            else:
                print(f"✗ {header:30s} - Missing")
            print(f"  Purpose: {description}\n")

        # Calculate security score
        present = sum(1 for h in important_headers if h in headers)
        score = (present / len(important_headers)) * 100

        print(f"\nSecurity Score: {score:.1f}%")

        if score < 50:
            print("⚠️ Warning: Poor security header implementation")
        elif score < 80:
            print("⚠️ Moderate security header implementation")
        else:
            print("✓ Good security header implementation")

    except Exception as e:
        print(f"Error checking headers: {e}")

# Example usage
# check_security_headers("https://example.com")
```

---

## Practical Exercises

### Exercise 1: Password Strength Checker
Create a program that:
- Accepts a password from user
- Checks length (minimum 12 characters)
- Checks for uppercase, lowercase, digits, special characters
- Checks against common passwords list
- Returns a strength score (0-100)

### Exercise 2: IP Blocklist Manager
Create a tool that:
- Maintains a list of blocked IP addresses
- Allows adding/removing IPs
- Checks if an IP is blocked
- Saves/loads the blocklist from a file
- Supports IP ranges (e.g., 192.168.1.0/24)

### Exercise 3: Log File Analyzer
Build a script that:
- Reads system logs
- Identifies failed login attempts
- Groups attempts by IP address
- Generates a report of suspicious IPs
- Exports results to CSV

### Exercise 4: File Integrity Checker
Develop a program that:
- Calculates hashes of important files
- Stores hashes in a database/file
- Periodically checks if files have been modified
- Alerts when changes are detected
- Generates integrity reports

### Exercise 5: Simple Vulnerability Scanner
Create a basic scanner that:
- Checks for common ports
- Identifies running services
- Checks for default credentials
- Tests for common misconfigurations
- Generates a security report

---

## Additional Resources

### Books
- "Black Hat Python" by Justin Seitz
- "Violent Python" by TJ O'Connor
- "Python for Cybersecurity" by Howard Poston

### Online Resources
- **OWASP Python Security Project**: https://owasp.org/www-project-python-security/
- **Real Python Security Tutorials**: https://realpython.com/tutorials/security/
- **Python Security Best Practices**: https://python.readthedocs.io/en/latest/library/security_warnings.html

### Practice Platforms
- **HackTheBox**: https://www.hackthebox.eu
- **TryHackMe**: https://tryhackme.com
- **PentesterLab**: https://pentesterlab.com
- **OverTheWire**: https://overthewire.org

### Python Security Libraries
- **Scapy**: Packet manipulation
- **Cryptography**: Encryption and cryptographic operations
- **PyCrypto**: Cryptographic algorithms
- **Requests**: HTTP library with security features
- **PyShark**: Python wrapper for tshark
- **Impacket**: Network protocols
- **Paramiko**: SSH2 protocol
- **BeautifulSoup**: Web scraping (for security testing)

### Security Certifications to Consider
- CompTIA Security+
- CEH (Certified Ethical Hacker)
- OSCP (Offensive Security Certified Professional)
- GIAC Security Essentials (GSEC)

---

## Best Practices for Security Programming

1. **Never hardcode credentials** - Use environment variables or secure vaults
2. **Validate all input** - Never trust user input
3. **Use strong encryption** - Industry-standard algorithms only
4. **Keep libraries updated** - Security patches are crucial
5. **Follow the principle of least privilege** - Minimal permissions needed
6. **Log security events** - Maintain audit trails
7. **Handle errors gracefully** - Don't expose system information
8. **Use secure random number generation** - `secrets` module, not `random`
9. **Implement rate limiting** - Prevent brute force attacks
10. **Regular security audits** - Review and test your code

### Secure Coding Example

```python
import secrets
import os
from cryptography.fernet import Fernet

# ✓ Good: Generate secure random token
secure_token = secrets.token_urlsafe(32)

# ✗ Bad: Weak random number
# import random
# weak_token = random.randint(1000, 9999)

# ✓ Good: Load credentials from environment
api_key = os.environ.get('API_KEY')
if not api_key:
    raise ValueError("API_KEY not set")

# ✗ Bad: Hardcoded credentials
# api_key = "hardcoded_secret_key_12345"

# ✓ Good: Proper error handling
try:
    result = perform_security_operation()
except Exception as e:
    log_error(f"Operation failed: {type(e).__name__}")
    print("An error occurred. Please contact support.")

# ✗ Bad: Exposing system info
# except Exception as e:
#     print(f"Error: {e}")
#     print(f"System path: {sys.path}")
```

---

## Legal and Ethical Considerations

**IMPORTANT REMINDER:**

1. **Only test systems you own or have explicit permission to test**
2. **Unauthorized access is illegal** - Even with good intentions
3. **Follow responsible disclosure** - Report vulnerabilities properly
4. **Respect privacy** - Handle data ethically
5. **Know your local laws** - Cybersecurity laws vary by country
6. **Get proper authorization** - Written permission before security testing
7. **Stay updated on regulations** - GDPR, CCPA, HIPAA, etc.

---

## Conclusion

This guide provides a foundation for using Python in cybersecurity. Remember:

- **Practice regularly** - Build projects and solve challenges
- **Stay curious** - Security is always evolving
- **Join communities** - Learn from other security professionals
- **Keep learning** - New threats emerge constantly
- **Use your skills ethically** - Always work on the defensive side

**Next Steps:**
1. Complete the practical exercises
2. Build your own security tools
3. Contribute to open-source security projects
4. Participate in CTF competitions
5. Consider pursuing security certifications

Good luck on your cybersecurity journey! 🔒🐍

---

*Last Updated: October 2025*
*Maintained for educational and defensive security purposes only*
