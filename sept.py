#!/usr/bin/env python3

import argparse
import socket
import threading
import os
import secrets
import logging
import base64
import uuid
import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from signal_protocol import (
    Address,
    InMemorySignalProtocolStore,
    SessionBuilder,
    SessionCipher,
    generate_identity_key_pair,
    generate_registration_id,
    generate_pre_keys,
    generate_signed_pre_key,
)
import google.auth
from googleapiclient.discovery import build

# Configure logging
logging.basicConfig(filename='secure_scanner.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecurePortScanner:
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        self.signal_store = InMemorySignalProtocolStore(
            generate_identity_key_pair(),
            generate_registration_id()
        )
        self.sessions = {}
        self._initialize_signal_keys()
        self.gui_running = False
        self.chat_history = []
        self.vanish_mode = False

    def _initialize_signal_keys(self):
        pre_keys = generate_pre_keys(0, 100)
        signed_pre_key = generate_signed_pre_key(self.signal_store.get_identity_key_pair(), 1)
        for pre_key in pre_keys:
            self.signal_store.store_pre_key(pre_key.get_id(), pre_key)
        self.signal_store.store_signed_pre_key(signed_pre_key.get_id(), signed_pre_key)

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
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
        return base64.b64encode(salt + iv + encryptor.tag + encrypted_data).decode()

    def generate_user_credentials(self):
        user_id = str(uuid.uuid4())
        secret = secrets.token_urlsafe(32)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            iterations=100000,
            backend=default_backend()
        )
        hashed_secret = base64.b64encode(kdf.derive(secret.encode())).decode()
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

    def port_scan(self, host, start_port, end_port, output_widget=None):
        results = {}
        threads = []
        lock = threading.Lock()
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.safe_update_results, args=(results, lock, host, port))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        if output_widget:
            for port, is_open in results.items():
                status = "open" if is_open else "closed"
                output_widget.insert(tk.END, f"Port {port}: {status}\n")
        return results

    def safe_update_results(self, results, lock, host, port):
        port_result = self.scan_port(host, port)
        with lock:
            results.update([port_result])

    def connect_to_google_voice(self, number, message, chat_widget):
        try:
            credentials, _ = google.auth.default()
            service = build('voice', 'v1', credentials=credentials)
            logger.info(f"Sending to Google Voice {number}: {message}")
            if chat_widget:
                chat_widget.insert(tk.END, f"Google Voice {number}: {message}\n", "sent")
        except google.auth.exceptions.DefaultCredentialsError as e:
            logger.error(f"Google authentication failed: {e}")
            if chat_widget:
                chat_widget.insert(tk.END, "Google Voice authentication failed. Ensure credentials are set up properly.\n", "error")
        except Exception as e:
            logger.error(f"Google Voice error: {e}")
            if chat_widget:
                chat_widget.insert(tk.END, f"Error: {e}\n", "error")

def install():
    scanner = SecurePortScanner()
    data = "Initial configuration data"
    encrypted_data = scanner.public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    with open("config.encrypted", "wb") as f:
        f.write(encrypted_data)
    with open("public_key.pem", "wb") as f:
        f.write(scanner.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    logger.info("Installation completed")
