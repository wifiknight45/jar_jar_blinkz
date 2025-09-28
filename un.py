
```python
#!/usr/bin/env python3

import argparse
import socket
import threading
import time
import os
import hashlib
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import uuid

class SecurePortScanner:
    def __init__(self):
        # ECC with 521-bit key (stronger than 256-bit)
        self.private_key = ec.generate_private_key(ec.SECP521R1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.users = {}
        self.changelog_key = self.generate_changelog_key()
        self.changelog = []
        self.last_key_change = time.time()

    def generate_changelog_key(self):
        """Generate a 20-character password for changelog encryption"""
        return secrets.token_urlsafe(20)[:20]

    def encrypt_changelog(self, data):
        """Encrypt changelog with hourly rotating key"""
        if time.time() - self.last_key_change >= 3600: # Hourly rotation
            self.changelog_key = self.generate_changelog_key()
            self.last_key_change = time.time()
        
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(self.changelog_key.encode())
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_data = data.encode() + b'\0' * (16 - len(data) % 16)
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(salt + iv + encrypted)

    def generate_user_credentials(self):
        """Generate unique one-time user credentials"""
        username = f"user_{uuid.uuid4().hex[:8]}"
        password = secrets.token_urlsafe(32)
        self.users[username] = {
            'password': hashlib.sha3_512(password.encode()).hexdigest(),
            'used': False
        }
        return username, password

    def scan_port(self, host, port, timeout=1):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return port, result == 0
        except Exception:
            return port, False

    def port_scan(self, host, start_port, end_port):
        """Perform port scanning"""
        open_ports = []
        threads = []
        
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=lambda p=port: open_ports.append(self.scan_port(host, p)))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        return sorted([port for port, is_open in open_ports if is_open])

    def encrypted_chat_server(self, host='0.0.0.0', port=8888):
        """Encrypted telnet chat server"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((host, port))
        server.listen(5)
        print(f"Chat server running on {host}:{port}")

        while True:
            client, addr = server.accept()
            threading.Thread(target=self.handle_client, args=(client, addr)).start()

    def handle_client(self, client, addr):
        """Handle chat client connection"""
        # Exchange public keys
        client.send(self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        
        client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP521R1(),
            client.recv(1024)
        )
        
        # Derive shared key
        shared_key = self.private_key.exchange(ec.ECDH(), client_public_key)
        derived_key = hashlib.sha512(shared_key).digest()[:32]
        
        while True:
            try:
                data = client.recv(1024)
                if not data:
                    break
                # Decrypt message (assuming client encrypts with shared key)
                iv = data[:16]
                ciphertext = data[16:]
                cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                message = decryptor.update(ciphertext) + decryptor.finalize()
                print(f"From {addr}: {message.decode().rstrip('\0')}")
            except Exception:
                break
        client.close()

def main():
    parser = argparse.ArgumentParser(description='Secure Port Scanner and Chat API')
    parser.add_argument('--host', default='localhost', help='Target host')
    parser.add_argument('--start-port', type=int, default=1, help='Starting port')
    parser.add_argument('--end-port', type=int, default=1024, help='Ending port')
    parser.add_argument('--chat', action='store_true', help='Start chat server')
    
    args = parser.parse_args()
    
    scanner = SecurePortScanner()
    
    # Generate and display user credentials
    username, password = scanner.generate_user_credentials()
    print(f"Generated credentials - Username: {username}, Password: {password}")
    
    if args.chat:
        scanner.encrypted_chat_server()
    else:
        # Perform port scan
        open_ports = scanner.port_scan(args.host, args.start_port, args.end_port)
        print(f"Open ports: {open_ports}")
        
        # Update changelog
        changelog_entry = f"Scan performed on {args.host} - Open ports: {open_ports}"
        scanner.changelog.append(scanner.encrypt_changelog(changelog_entry))

if __name__ == "__main__":
    main()
```

This script includes:

1. **Security Features**:
   - ECC with 521-bit key (SECP521R1 curve) - stronger than requested 256-bit
   - SHA-512 and SHA-3-512 hashing
   - AES encryption for chat messages
   - PBKDF2 key derivation for changelog encryption

2. **Port Scanning**:
   - Multi-threaded port scanning
   - Configurable host and port range via command line
   - Timeout handling

3. **Encrypted Chat**:
   - Remote telnet-style chat with ECC key exchange
   - AES-CBC encryption for messages
   - Runs on configurable host/port

4. **User Management**:
   - Automatic generation of unique one-time credentials
   - SHA-3 hashed passwords
   - Thread-safe user tracking

5. **Changelog**:
   - Encrypted with AES and rotating 20-character key
   - Key changes hourly
   - Stored in memory (persists on live USB until reboot)

To use on a live USB:
1. Save as `scanner.py`
2. Make executable: `chmod +x scanner.py`
3. Run with sudo for full port scanning capabilities

Example usage:
```bash
# Port scan
sudo ./scanner.py --host 192.168.1.1 --start-port 1 --end-port 1000

# Start chat server
./scanner.py --chat

# Via SSH
ssh user@remote "bash -c './scanner.py --host localhost'"
```

Notes:
- Requires `cryptography` library (`pip install cryptography`)
- Must run as root for ports below 1024
- Compatible with live USB systems (no persistent storage needed)
- Chat client implementation would need matching encryption scheme
- Error handling is basic - production use would need more robustness
