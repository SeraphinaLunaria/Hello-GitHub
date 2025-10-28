# Python Cybersecurity Exercises

Practice problems to reinforce your Python cybersecurity skills. Start with easier exercises and progress to more complex challenges.

## Beginner Exercises

### Exercise 1: Basic Password Validator
**Difficulty:** Easy
**Concepts:** Strings, conditionals, functions

Write a function that validates passwords with these rules:
- Minimum 8 characters
- Contains at least one uppercase letter
- Contains at least one lowercase letter
- Contains at least one digit

```python
def validate_password(password):
    # Your code here
    pass

# Test cases
print(validate_password("Pass123"))  # Should return True
print(validate_password("weak"))     # Should return False
```

<details>
<summary>Solution</summary>

```python
def validate_password(password):
    """Validate password against security requirements"""
    if len(password) < 8:
        return False

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)

    return has_upper and has_lower and has_digit

# Test
print(validate_password("Pass123"))   # True
print(validate_password("weak"))      # False
print(validate_password("PASSWORD1")) # True
print(validate_password("nodigits"))  # False
```
</details>

---

### Exercise 2: IP Address Classifier
**Difficulty:** Easy
**Concepts:** String manipulation, conditionals

Create a function that determines if an IP address is:
- Private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Loopback (127.0.0.0/8)
- Public (everything else)

```python
def classify_ip(ip_address):
    # Your code here
    pass

# Test cases
print(classify_ip("192.168.1.1"))   # Should return "private"
print(classify_ip("8.8.8.8"))       # Should return "public"
print(classify_ip("127.0.0.1"))     # Should return "loopback"
```

<details>
<summary>Solution</summary>

```python
import ipaddress

def classify_ip(ip_address):
    """Classify IP address type"""
    try:
        ip = ipaddress.ip_address(ip_address)

        if ip.is_loopback:
            return "loopback"
        elif ip.is_private:
            return "private"
        elif ip.is_global:
            return "public"
        else:
            return "special"

    except ValueError:
        return "invalid"

# Test
print(classify_ip("192.168.1.1"))   # private
print(classify_ip("8.8.8.8"))       # public
print(classify_ip("127.0.0.1"))     # loopback
print(classify_ip("10.0.0.1"))      # private
```
</details>

---

### Exercise 3: File Hash Calculator
**Difficulty:** Easy
**Concepts:** File I/O, hashlib

Write a function that calculates the SHA-256 hash of a file.

```python
import hashlib

def calculate_file_hash(filename):
    # Your code here
    pass

# Test
hash_value = calculate_file_hash("test.txt")
print(f"File hash: {hash_value}")
```

<details>
<summary>Solution</summary>

```python
import hashlib

def calculate_file_hash(filename):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()

    try:
        with open(filename, "rb") as f:
            # Read in 4K chunks
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()

    except FileNotFoundError:
        print(f"File {filename} not found")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

# Create test file and calculate hash
with open("test.txt", "w") as f:
    f.write("Hello, World!")

hash_value = calculate_file_hash("test.txt")
print(f"File hash: {hash_value}")
```
</details>

---

## Intermediate Exercises

### Exercise 4: Log Parser
**Difficulty:** Medium
**Concepts:** Regular expressions, file I/O, dictionaries

Parse a log file and extract failed SSH login attempts. Count attempts per IP address.

```python
import re
from collections import Counter

def parse_ssh_logs(log_file):
    # Your code here
    # Return dictionary with IP addresses and attempt counts
    pass

# Test with sample log
sample_log = """
Oct 28 10:15:23 sshd[1234]: Failed password for root from 192.168.1.100
Oct 28 10:15:45 sshd[1235]: Failed password for admin from 192.168.1.100
Oct 28 10:16:12 sshd[1236]: Failed password for user from 10.0.0.50
Oct 28 10:16:34 sshd[1237]: Accepted password for alice from 192.168.1.200
"""
```

<details>
<summary>Solution</summary>

```python
import re
from collections import Counter

def parse_ssh_logs(log_content):
    """Parse SSH logs and count failed attempts by IP"""
    failed_attempts = Counter()

    # Pattern for failed SSH attempts
    pattern = r'Failed password for \w+ from ([\d.]+)'

    for line in log_content.split('\n'):
        match = re.search(pattern, line)
        if match:
            ip_address = match.group(1)
            failed_attempts[ip_address] += 1

    return dict(failed_attempts)

# Test
sample_log = """
Oct 28 10:15:23 sshd[1234]: Failed password for root from 192.168.1.100
Oct 28 10:15:45 sshd[1235]: Failed password for admin from 192.168.1.100
Oct 28 10:16:12 sshd[1236]: Failed password for user from 10.0.0.50
Oct 28 10:16:34 sshd[1237]: Accepted password for alice from 192.168.1.200
"""

results = parse_ssh_logs(sample_log)
print("Failed login attempts by IP:")
for ip, count in sorted(results.items(), key=lambda x: x[1], reverse=True):
    print(f"  {ip}: {count} attempts")

# Output:
# 192.168.1.100: 2 attempts
# 10.0.0.50: 1 attempts
```
</details>

---

### Exercise 5: Caesar Cipher
**Difficulty:** Medium
**Concepts:** String manipulation, algorithms

Implement a Caesar cipher encoder and decoder.

```python
def caesar_encrypt(text, shift):
    # Your code here
    pass

def caesar_decrypt(text, shift):
    # Your code here
    pass

# Test
encrypted = caesar_encrypt("HELLO", 3)
print(f"Encrypted: {encrypted}")  # Should be "KHOOR"

decrypted = caesar_decrypt(encrypted, 3)
print(f"Decrypted: {decrypted}")  # Should be "HELLO"
```

<details>
<summary>Solution</summary>

```python
def caesar_encrypt(text, shift):
    """Encrypt text using Caesar cipher"""
    result = ""

    for char in text:
        if char.isupper():
            # Shift uppercase letters
            result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower():
            # Shift lowercase letters
            result += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            # Keep non-alphabetic characters unchanged
            result += char

    return result

def caesar_decrypt(text, shift):
    """Decrypt Caesar cipher by shifting backwards"""
    return caesar_encrypt(text, -shift)

# Test
message = "HELLO WORLD"
shift = 3

encrypted = caesar_encrypt(message, shift)
print(f"Original:  {message}")
print(f"Encrypted: {encrypted}")

decrypted = caesar_decrypt(encrypted, shift)
print(f"Decrypted: {decrypted}")

# Test with lowercase
message2 = "Python Security"
encrypted2 = caesar_encrypt(message2, 5)
decrypted2 = caesar_decrypt(encrypted2, 5)

print(f"\nOriginal:  {message2}")
print(f"Encrypted: {encrypted2}")
print(f"Decrypted: {decrypted2}")
```
</details>

---

### Exercise 6: Port Scanner
**Difficulty:** Medium
**Concepts:** Networking, sockets, error handling

Create a simple port scanner that checks if specified ports are open on localhost.

**WARNING:** Only scan systems you own!

```python
import socket

def scan_ports(host, ports):
    # Your code here
    # Return list of open ports
    pass

# Test (only on localhost!)
open_ports = scan_ports("127.0.0.1", [22, 80, 443, 3306, 8080])
print(f"Open ports: {open_ports}")
```

<details>
<summary>Solution</summary>

```python
import socket
from datetime import datetime

def scan_port(host, port, timeout=1):
    """Check if a single port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except socket.error:
        return False

def scan_ports(host, ports):
    """Scan multiple ports and return open ones"""
    open_ports = []

    print(f"\n[*] Starting scan on {host}")
    print(f"[*] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)

    for port in ports:
        if scan_port(host, port):
            print(f"[+] Port {port:5d} - OPEN")
            open_ports.append(port)
        else:
            print(f"[-] Port {port:5d} - Closed")

    print("-" * 50)
    print(f"[*] Scan complete. Found {len(open_ports)} open ports")

    return open_ports

# Test on localhost only
common_ports = [21, 22, 80, 443, 3306, 5432, 8080, 8888]
open_ports = scan_ports("127.0.0.1", common_ports)

print(f"\nOpen ports on localhost: {open_ports}")
```
</details>

---

## Advanced Exercises

### Exercise 7: Brute Force Detector
**Difficulty:** Hard
**Concepts:** Data structures, time-based analysis, algorithms

Create a system that detects brute force attacks by monitoring failed login attempts.

Requirements:
- Track failed attempts per IP address
- Flag IPs with 5+ failures in 10 minutes
- Implement auto-blocking after threshold
- Generate alerts

```python
from datetime import datetime, timedelta
from collections import defaultdict

class BruteForceDetector:
    def __init__(self, threshold=5, timeframe=600):
        # Your code here
        pass

    def record_failed_attempt(self, ip_address):
        # Your code here
        pass

    def is_blocked(self, ip_address):
        # Your code here
        pass

# Test the detector
```

<details>
<summary>Solution</summary>

```python
from datetime import datetime, timedelta
from collections import defaultdict

class BruteForceDetector:
    """Detect and block brute force attacks"""

    def __init__(self, threshold=5, timeframe=600):
        """
        Initialize detector

        Args:
            threshold: Number of failed attempts before blocking
            timeframe: Time window in seconds
        """
        self.threshold = threshold
        self.timeframe = timeframe
        self.failed_attempts = defaultdict(list)
        self.blocked_ips = set()

    def record_failed_attempt(self, ip_address):
        """Record a failed login attempt"""
        current_time = datetime.now()

        # Add attempt to history
        self.failed_attempts[ip_address].append(current_time)

        # Clean old attempts outside timeframe
        cutoff_time = current_time - timedelta(seconds=self.timeframe)
        self.failed_attempts[ip_address] = [
            t for t in self.failed_attempts[ip_address]
            if t > cutoff_time
        ]

        # Check if threshold exceeded
        attempt_count = len(self.failed_attempts[ip_address])

        if attempt_count >= self.threshold:
            if ip_address not in self.blocked_ips:
                self.blocked_ips.add(ip_address)
                self.generate_alert(ip_address, attempt_count)
                return True

        return False

    def is_blocked(self, ip_address):
        """Check if IP is blocked"""
        return ip_address in self.blocked_ips

    def unblock_ip(self, ip_address):
        """Manually unblock an IP"""
        if ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
            self.failed_attempts[ip_address] = []
            print(f"✓ Unblocked {ip_address}")
            return True
        return False

    def generate_alert(self, ip_address, attempt_count):
        """Generate security alert"""
        print(f"\n{'='*60}")
        print(f"⚠️ SECURITY ALERT - BRUTE FORCE DETECTED")
        print(f"{'='*60}")
        print(f"IP Address: {ip_address}")
        print(f"Failed Attempts: {attempt_count}")
        print(f"Timeframe: {self.timeframe} seconds")
        print(f"Status: BLOCKED")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")

    def get_statistics(self):
        """Get current statistics"""
        print(f"\n{'='*60}")
        print(f"BRUTE FORCE DETECTOR STATISTICS")
        print(f"{'='*60}")
        print(f"\nBlocked IPs: {len(self.blocked_ips)}")
        print(f"Monitored IPs: {len(self.failed_attempts)}")

        if self.blocked_ips:
            print(f"\n--- Blocked IP Addresses ---")
            for ip in sorted(self.blocked_ips):
                count = len(self.failed_attempts[ip])
                print(f"  {ip}: {count} attempts")

        print(f"\n--- Recent Failed Attempts ---")
        for ip, attempts in sorted(self.failed_attempts.items(),
                                   key=lambda x: len(x[1]),
                                   reverse=True)[:5]:
            if attempts:
                print(f"  {ip}: {len(attempts)} attempts")

        print(f"{'='*60}\n")

# Test
detector = BruteForceDetector(threshold=5, timeframe=600)

# Simulate failed login attempts
test_ips = ["192.168.1.100", "10.0.0.50", "192.168.1.100"]

print("Simulating login attempts...")
for i in range(7):
    ip = "192.168.1.100"
    print(f"\nAttempt {i+1} from {ip}")
    blocked = detector.record_failed_attempt(ip)

    if blocked:
        print(f"✗ IP {ip} has been blocked!")

# Check if blocked
print(f"\nIs 192.168.1.100 blocked? {detector.is_blocked('192.168.1.100')}")

# Get statistics
detector.get_statistics()

# Unblock
detector.unblock_ip("192.168.1.100")
```
</details>

---

### Exercise 8: Network Traffic Analyzer
**Difficulty:** Hard
**Concepts:** Network protocols, packet analysis, data structures

Build a basic network traffic analyzer that processes packet data and identifies suspicious patterns.

```python
class NetworkTrafficAnalyzer:
    def __init__(self):
        # Your code here
        pass

    def analyze_packet(self, packet_data):
        # Your code here
        pass

    def detect_port_scan(self):
        # Your code here
        pass

    def generate_report(self):
        # Your code here
        pass
```

<details>
<summary>Solution</summary>

```python
from collections import defaultdict, Counter
from datetime import datetime

class NetworkTrafficAnalyzer:
    """Analyze network traffic for suspicious patterns"""

    def __init__(self):
        self.packets = []
        self.connections = defaultdict(set)  # IP -> set of ports
        self.connection_counts = Counter()   # (src_ip, dst_ip) -> count
        self.port_scans = []
        self.suspicious_ips = set()

    def analyze_packet(self, src_ip, dst_ip, dst_port, protocol="TCP"):
        """Analyze a single packet"""
        timestamp = datetime.now()

        packet = {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'protocol': protocol
        }

        self.packets.append(packet)

        # Track connections
        self.connections[src_ip].add(dst_port)
        self.connection_counts[(src_ip, dst_ip)] += 1

        # Detect port scanning (one IP accessing many ports)
        if len(self.connections[src_ip]) > 10:
            if src_ip not in self.suspicious_ips:
                self.port_scans.append({
                    'ip': src_ip,
                    'ports': len(self.connections[src_ip]),
                    'timestamp': timestamp
                })
                self.suspicious_ips.add(src_ip)

    def detect_port_scan(self):
        """Identify potential port scans"""
        port_scanners = []

        for ip, ports in self.connections.items():
            if len(ports) > 10:  # Threshold for port scan
                port_scanners.append({
                    'ip': ip,
                    'ports_accessed': len(ports),
                    'ports': sorted(ports)
                })

        return port_scanners

    def detect_syn_flood(self):
        """Detect potential SYN flood attacks"""
        # Count connections per IP pair
        syn_floods = []

        for (src_ip, dst_ip), count in self.connection_counts.items():
            if count > 100:  # Threshold
                syn_floods.append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'connection_count': count
                })

        return syn_floods

    def generate_report(self):
        """Generate traffic analysis report"""
        print("\n" + "="*70)
        print("NETWORK TRAFFIC ANALYSIS REPORT")
        print("="*70)

        print(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Packets Analyzed: {len(self.packets)}")
        print(f"Unique Source IPs: {len(self.connections)}")

        # Port scan detection
        port_scans = self.detect_port_scan()
        print(f"\n--- Potential Port Scans ({len(port_scans)}) ---")
        if port_scans:
            for scan in port_scans:
                print(f"\n⚠️ Suspicious Activity Detected")
                print(f"  Source IP: {scan['ip']}")
                print(f"  Ports Accessed: {scan['ports_accessed']}")
                print(f"  Sample Ports: {scan['ports'][:10]}")
        else:
            print("  ✓ No port scans detected")

        # SYN flood detection
        syn_floods = self.detect_syn_flood()
        print(f"\n--- Potential SYN Floods ({len(syn_floods)}) ---")
        if syn_floods:
            for flood in syn_floods:
                print(f"\n⚠️ Possible SYN Flood Attack")
                print(f"  Source: {flood['src_ip']}")
                print(f"  Target: {flood['dst_ip']}")
                print(f"  Connections: {flood['connection_count']}")
        else:
            print("  ✓ No SYN floods detected")

        # Top talkers
        print(f"\n--- Top Traffic Sources ---")
        top_ips = Counter()
        for packet in self.packets:
            top_ips[packet['src_ip']] += 1

        for ip, count in top_ips.most_common(5):
            print(f"  {ip}: {count} packets")

        print("\n" + "="*70)

# Test
analyzer = NetworkTrafficAnalyzer()

# Simulate normal traffic
print("Simulating network traffic...\n")
analyzer.analyze_packet("192.168.1.10", "10.0.0.1", 80)
analyzer.analyze_packet("192.168.1.10", "10.0.0.1", 443)
analyzer.analyze_packet("192.168.1.20", "10.0.0.1", 22)

# Simulate port scan
print("Simulating port scan from 192.168.1.100...")
for port in range(20, 50):
    analyzer.analyze_packet("192.168.1.100", "10.0.0.1", port)

# Simulate SYN flood
print("Simulating high connection volume from 192.168.1.200...")
for i in range(150):
    analyzer.analyze_packet("192.168.1.200", "10.0.0.1", 80)

# Generate report
analyzer.generate_report()
```
</details>

---

### Exercise 9: Encryption System
**Difficulty:** Hard
**Concepts:** Cryptography, file I/O, key management

Build a complete file encryption/decryption system with key management.

```python
from cryptography.fernet import Fernet

class FileEncryptionSystem:
    def __init__(self):
        # Your code here
        pass

    def generate_key(self):
        # Your code here
        pass

    def encrypt_file(self, filename):
        # Your code here
        pass

    def decrypt_file(self, filename):
        # Your code here
        pass
```

<details>
<summary>Solution</summary>

```python
from cryptography.fernet import Fernet
import os

class FileEncryptionSystem:
    """Complete file encryption/decryption system"""

    def __init__(self, key_file="encryption.key"):
        self.key_file = key_file
        self.key = None
        self.cipher = None

    def generate_key(self):
        """Generate new encryption key"""
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

        # Save key to file
        with open(self.key_file, 'wb') as f:
            f.write(self.key)

        print(f"✓ Generated new encryption key")
        print(f"✓ Key saved to {self.key_file}")
        print(f"⚠️ Keep this key file secure!")

        return self.key

    def load_key(self):
        """Load existing encryption key"""
        if not os.path.exists(self.key_file):
            print(f"✗ Key file not found: {self.key_file}")
            return False

        with open(self.key_file, 'rb') as f:
            self.key = f.read()

        self.cipher = Fernet(self.key)
        print(f"✓ Loaded encryption key from {self.key_file}")
        return True

    def encrypt_file(self, filename):
        """Encrypt a file"""
        if not self.cipher:
            print("✗ No encryption key loaded")
            return False

        if not os.path.exists(filename):
            print(f"✗ File not found: {filename}")
            return False

        try:
            # Read file
            with open(filename, 'rb') as f:
                file_data = f.read()

            # Encrypt
            encrypted_data = self.cipher.encrypt(file_data)

            # Write encrypted file
            encrypted_filename = filename + '.encrypted'
            with open(encrypted_filename, 'wb') as f:
                f.write(encrypted_data)

            print(f"✓ File encrypted successfully")
            print(f"✓ Encrypted file: {encrypted_filename}")
            return True

        except Exception as e:
            print(f"✗ Encryption failed: {e}")
            return False

    def decrypt_file(self, filename):
        """Decrypt a file"""
        if not self.cipher:
            print("✗ No encryption key loaded")
            return False

        if not os.path.exists(filename):
            print(f"✗ File not found: {filename}")
            return False

        try:
            # Read encrypted file
            with open(filename, 'rb') as f:
                encrypted_data = f.read()

            # Decrypt
            decrypted_data = self.cipher.decrypt(encrypted_data)

            # Write decrypted file
            if filename.endswith('.encrypted'):
                decrypted_filename = filename[:-10]  # Remove .encrypted
            else:
                decrypted_filename = filename + '.decrypted'

            with open(decrypted_filename, 'wb') as f:
                f.write(decrypted_data)

            print(f"✓ File decrypted successfully")
            print(f"✓ Decrypted file: {decrypted_filename}")
            return True

        except Exception as e:
            print(f"✗ Decryption failed: {e}")
            print(f"⚠️ Wrong key or corrupted file")
            return False

    def encrypt_directory(self, directory):
        """Encrypt all files in a directory"""
        if not os.path.exists(directory):
            print(f"✗ Directory not found: {directory}")
            return 0

        encrypted_count = 0

        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)

            if os.path.isfile(filepath) and not filepath.endswith('.encrypted'):
                if self.encrypt_file(filepath):
                    encrypted_count += 1

        print(f"\n✓ Encrypted {encrypted_count} files")
        return encrypted_count

# Test
system = FileEncryptionSystem()

# Generate key
system.generate_key()

# Create test file
test_file = "secret_data.txt"
with open(test_file, 'w') as f:
    f.write("This is sensitive information!\n")
    f.write("Database password: admin123\n")
    f.write("API key: secret_key_12345\n")

print(f"\n--- Original File ---")
with open(test_file, 'r') as f:
    print(f.read())

# Encrypt
print("\n--- Encrypting File ---")
system.encrypt_file(test_file)

# Show encrypted content
print("\n--- Encrypted File (Binary) ---")
with open(test_file + '.encrypted', 'rb') as f:
    print(f"First 50 bytes: {f.read(50)}")

# Decrypt
print("\n--- Decrypting File ---")
system.decrypt_file(test_file + '.encrypted')

# Show decrypted content
print("\n--- Decrypted File ---")
with open(test_file, 'r') as f:
    print(f.read())

# Clean up
os.remove(test_file)
os.remove(test_file + '.encrypted')
os.remove(system.key_file)
print("\n✓ Test files cleaned up")
```
</details>

---

## Challenge Projects

### Project 1: Security Audit Tool
Build a comprehensive security audit tool that:
- Scans system for common vulnerabilities
- Checks file permissions
- Audits installed software
- Checks for default credentials
- Generates detailed report

### Project 2: Intrusion Detection System (IDS)
Create a basic IDS that:
- Monitors network traffic
- Detects suspicious patterns
- Identifies known attack signatures
- Generates real-time alerts
- Logs security events

### Project 3: Password Manager
Develop a secure password manager with:
- Master password authentication
- Encrypted storage
- Password generation
- Auto-fill capabilities
- Secure backup/restore

### Project 4: Web Application Firewall (WAF)
Build a simple WAF that:
- Filters HTTP requests
- Blocks SQL injection attempts
- Prevents XSS attacks
- Implements rate limiting
- Logs suspicious requests

---

## Tips for Success

1. **Start Simple:** Begin with easier exercises and gradually progress
2. **Test Thoroughly:** Always test your code with various inputs
3. **Read Documentation:** Familiarize yourself with library documentation
4. **Practice Regularly:** Consistency is key to mastering security programming
5. **Ask Questions:** Join communities and ask for help when stuck
6. **Build Projects:** Apply your skills to real-world projects
7. **Stay Ethical:** Always use your skills responsibly and legally

## Additional Resources

- Python documentation: https://docs.python.org
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Practice platforms: HackTheBox, TryHackMe, PentesterLab
- CTF competitions: picoCTF, OverTheWire

---

Good luck with your exercises! Remember, the best way to learn is by doing. 🔒
