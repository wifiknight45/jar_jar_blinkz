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
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import signal_protocol  # Assume you've installed the signal-protocol-python library

# Configure logging
logging.basicConfig(filename='secure_scanner.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecurePortScanner:
    def __init__(self):
        self.signal_store = signal_protocol.InMemoryStore()  # Or a persistent store

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
            with socket.create_connection((host, port), timeout=timeout) as sock:
                return port, True
        except socket.timeout:
            logger.warning(f"Timeout scanning port {port} on {host}")
            return port, False
        except ConnectionRefusedError:
            logger.info(f"Connection refused to port {port} on {host}")
            return port, False
        except OSError as e:
            logger.error(f"OSError scanning port {port} on {host}: {e}")
            return port, False
        except Exception as e:
            logger.exception(f"Unexpected error scanning port {port} on {host}: {e}")
            return port, False

    def port_scan(self, host, start_port, end_port):
        results = {}
        for port in range(start_port, end_port + 1):
            port, is_open = self.scan_port(host, port)
            results[port] = is_open
        return results

    def encrypted_chat_server(self, host='0.0.0.0', port=8888):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((host, port))
        server.listen(5)
        logger.info(f"Chat server started on {host}:{port}")

        while True:
            client, addr = server.accept()
            threading.Thread(target=self.handle_client, args=(client, addr)).start()

    def handle_client(self, client, addr):
        """Handle chat client connection with Signal Protocol"""
        try:
            recipient_id = "recipient_id"  # Replace with actual recipient ID
            device_id = 1  # Replace with actual device ID
            session_builder = signal_protocol.SessionBuilder(self.signal_store, recipient_id, device_id)
            session_cipher = signal_protocol.SessionCipher(self.signal_store, recipient_id, device_id)

            while True:
                try:
                    data = client.recv(1024)
                    if not data:
                        break
                    # Decrypt message using Signal Protocol
                    plaintext = session_cipher.decrypt(data)
                    logger.info(f"Received message from {addr}: {plaintext.decode()}")
                    # ... (process plaintext message) ...
                except Exception as e:
                    logger.error(f"Error handling client {addr}: {e}")
                    break

            client.close()
        except Exception as e:
            logger.exception(f"Error establishing Signal Protocol session with {addr}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Secure Port Scanner and Encrypted Chat Server")
    parser.add_argument('--chat', action='store_true', help="Start the encrypted chat server")
    parser.add_argument('--scan', action='store_true', help="Perform a port scan")
    parser.add_argument('--host', type=str, default='localhost', help="Host to scan or bind server")
    parser.add_argument('--start-port', type=int, default=1, help="Start port for scanning")
    parser.add_argument('--end-port', type=int, default=65535, help="End port for scanning")
    args = parser.parse_args()

    scanner = SecurePortScanner()

    if args.chat:
        scanner.encrypted_chat_server(host=args.host)
    elif args.scan:
        results = scanner.port_scan(args.host, args.start_port, args.end_port)
        for port, is_open in results.items():
            status = "open" if is_open else "closed"
            logger.info(f"Port {port} is {status}")

def install():
    """Encrypted installation with persistence"""
    public_key, private_key = rsa.newkeys(2048)
    data = "sensitive data to encrypt"  # This should be the actual sensitive data
    encrypted_data = rsa.encrypt(data.encode(), public_key)

    with open("config.encrypted", "wb") as f:
        f.write(encrypted_data)
    with open("public_key.pem", "wb") as f:
        f.write(public_key.save_pkcs1())

if __name__ == "__main__":
    if os.path.exists("config.encrypted"):
        main()
    else:
        install()
