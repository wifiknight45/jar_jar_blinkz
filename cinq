#!/usr/bin/env python3

import argparse
import socket
import threading
import time
import os
import hashlib
import secrets
import logging
import base64
import uuid
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(filename='secure_scanner.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecurePortScanner:
    def __init__(self):
        # Generate RSA key pair for installation
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def generate_changelog_key(self):
        salt = os.urandom(16)
        password = secrets.token_urlsafe(32).encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password)
        return key, salt, password.decode()

    def encrypt_changelog(self, data, key, salt):
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(key),
            modes.CFB(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
        return base64.b64encode(salt + iv + encrypted_data).decode()

    def generate_user_credentials(self):
        user_id = str(uuid.uuid4())
        secret = secrets.token_urlsafe(32)
        hashed_secret = hashlib.sha256(secret.encode()).hexdigest()
        return user_id, secret, hashed_secret

    def scan_port(self, host, port, timeout=1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    logger.info(f"Port {port} is open on {host}")
                    return port, True
                else:
                    logger.info(f"Port {port} is closed on {host}")
                    return port, False
        except socket.timeout:
            logger.warning(f"Timeout scanning port {port} on {host}")
            return port, False
        except Exception as e:
            logger.error(f"Error scanning port {port} on {host}: {e}")
            return port, False

    def port_scan(self, host, start_port, end_port):
        results = {}
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=lambda p=port: results.update([self.scan_port(host, p)]))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        return results

    def encrypted_chat_server(self, host='0.0.0.0', port=8888):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((host, port))
            server.listen(5)
            logger.info(f"Chat server started on {host}:{port}")

            while True:
                client, addr = server.accept()
                logger.info(f"New connection from {addr}")
                threading.Thread(target=self.handle_client, args=(client, addr)).start()
        except Exception as e:
            logger.error(f"Chat server error: {e}")
        finally:
            server.close()

    def handle_client(self, client, addr):
        try:
            while True:
                data = client.recv(1024)
                if not data:
                    break
                # Simple echo server (replace with Signal Protocol in production)
                client.send(data)
                logger.info(f"Received from {addr}: {data.decode('utf-8', errors='ignore')}")
        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}")
        finally:
            client.close()

def main():
    parser = argparse.ArgumentParser(description="Secure Port Scanner and Encrypted Chat Server")
    parser.add_argument('--chat', action='store_true', help="Start the encrypted chat server")
    parser.add_argument('--scan', action='store_true', help="Perform a port scan")
    parser.add_argument('--host', type=str, default='localhost', help="Host to scan or bind server")
    parser.add_argument('--start-port', type=int, default=1, help="Start port for scanning")
    parser.add_argument('--end-port', type=int, default=65535, help="End port for scanning")
    args = parser.parse_args()

    scanner = SecurePortScanner()
    user_id, secret, hashed_secret = scanner.generate_user_credentials()
    logger.info(f"Generated credentials - User ID: {user_id}, Secret: {secret}")

    if args.chat:
        scanner.encrypted_chat_server(host=args.host)
    elif args.scan:
        results = scanner.port_scan(args.host, args.start_port, args.end_port)
        for port, is_open in results.items():
            status = "open" if is_open else "closed"
            logger.info(f"Port {port} is {status}")
    else:
        print("Please specify either --chat or --scan")
        parser.print_help()

def install():
    scanner = SecurePortScanner()
    data = "Initial configuration data"
    encrypted_data = scanner.public_key.encrypt(
        data.encode(),
        padding=None  # Note: In production, use proper padding like OAEP
    )
    
    with open("config.encrypted", "wb") as f:
        f.write(encrypted_data)
    with open("public_key.pem", "wb") as f:
        f.write(scanner.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    logger.info("Installation completed")

if __name__ == "__main__":
    if os.path.exists("config.encrypted"):
        main()
    else:
        install()
