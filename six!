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
import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
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
import google.auth  # Requires google-auth-oauthlib, google-auth-httplib2
from googleapiclient.discovery import build  # Requires google-api-python-client

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

    def port_scan(self, host, start_port, end_port, output_widget=None):
        results = {}
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=lambda p=port: results.update([self.scan_port(host, p)]))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        if output_widget:
            for port, is_open in results.items():
                status = "open" if is_open else "closed"
                output_widget.insert(tk.END, f"Port {port}: {status}\n")
        return results

    def encrypted_chat_server(self, host='0.0.0.0', port=8888, status_widget=None, chat_widget=None):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((host, port))
            self.server.listen(5)
            logger.info(f"Chat server started on {host}:{port}")
            if status_widget:
                status_widget.config(text=f"Server running on {host}:{port}")

            while self.gui_running:
                client, addr = self.server.accept()
                client_id = f"{addr[0]}:{addr[1]}"
                logger.info(f"New connection from {client_id}")
                threading.Thread(target=self.handle_client, args=(client, client_id, chat_widget)).start()
        except Exception as e:
            logger.error(f"Chat server error: {e}")
            if status_widget:
                status_widget.config(text=f"Server error: {e}")
        finally:
            if hasattr(self, 'server'):
                self.server.close()

    def handle_client(self, client, client_id, chat_widget):
        try:
            address = Address(client_id, 1)
            session_builder = SessionBuilder(self.signal_store, address)
            initial_message = client.recv(1024)
            if initial_message:
                session_builder.process_pre_key_bundle(initial_message)
                self.sessions[client_id] = SessionCipher(self.signal_store, address)
                client.send(b"SESSION_ESTABLISHED")

            cipher = self.sessions[client_id]
            while True:
                data = client.recv(1024)
                if not data:
                    break
                plaintext = cipher.decrypt(data)
                message = plaintext.decode('utf-8')
                display_msg = message if not self.vanish_mode else message.encode().hex()
                logger.info(f"Received from {client_id}: {message}")
                if chat_widget:
                    chat_widget.insert(tk.END, f"{client_id}: {display_msg}\n", "received")
                    chat_widget.see(tk.END)
                response = f"Echo: {message}".encode('utf-8')
                encrypted_response = cipher.encrypt(response)
                client.send(encrypted_response)
        except Exception as e:
            logger.error(f"Error handling client {client_id}: {e}")
        finally:
            if client_id in self.sessions:
                del self.sessions[client_id]
            client.close()

    def connect_to_google_voice(self, number, message, chat_widget):
        # Placeholder for Google Voice API (requires proper credentials setup)
        try:
            # This requires Google Voice API credentials setup in your environment
            service = build('voice', 'v1', credentials=google.auth.default()[0])
            # Simplified - actual implementation would need proper API calls
            logger.info(f"Sending to Google Voice {number}: {message}")
            if chat_widget:
                chat_widget.insert(tk.END, f"Google Voice {number}: {message}\n", "sent")
        except Exception as e:
            logger.error(f"Google Voice error: {e}")
            if chat_widget:
                chat_widget.insert(tk.END, f"Error: {e}\n", "error")

    def connect_to_signal(self, number, message, chat_widget):
        # Placeholder for Signal Messenger integration (requires Signal CLI or similar)
        try:
            # This would typically use Signal CLI or a Signal API
            logger.info(f"Sending to Signal {number}: {message}")
            if chat_widget:
                chat_widget.insert(tk.END, f"Signal {number}: {message}\n", "sent")
        except Exception as e:
            logger.error(f"Signal error: {e}")
            if chat_widget:
                chat_widget.insert(tk.END, f"Error: {e}\n", "error")

    def run_gui(self):
        self.gui_running = True
        root = tk.Tk()
        root.title("Secure Scanner GUI")
        root.geometry("800x600")
        root.configure(bg="#f0f0f0")

        style = ttk.Style()
        style.configure("TButton", font=("Helvetica", 10), padding=5)
        style.configure("TLabel", font=("Helvetica", 10), background="#f0f0f0")
        style.configure("TFrame", background="#f0f0f0")

        # Port Scanner Frame
        scan_frame = ttk.LabelFrame(root, text="Port Scanner")
        scan_frame.pack(padx=10, pady=5, fill="x")

        ttk.Label(scan_frame, text="Host:").grid(row=0, column=0, padx=5, pady=5)
        host_entry = ttk.Entry(scan_frame)
        host_entry.grid(row=0, column=1, padx=5, pady=5)
        host_entry.insert(0, "localhost")

        ttk.Label(scan_frame, text="Start Port:").grid(row=1, column=0, padx=5, pady=5)
        start_port = ttk.Entry(scan_frame)
        start_port.grid(row=1, column=1, padx=5, pady=5)
        start_port.insert(0, "1")

        ttk.Label(scan_frame, text="End Port:").grid(row=2, column=0, padx=5, pady=5)
        end_port = ttk.Entry(scan_frame)
        end_port.grid(row=2, column=1, padx=5, pady=5)
        end_port.insert(0, "100")

        output_text = tk.Text(scan_frame, height=5, width=60, bg="#ffffff", font=("Courier", 10))
        output_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

        ttk.Button(scan_frame, text="Scan", command=lambda: threading.Thread(
            target=self.port_scan, args=(host_entry.get(), int(start_port.get()), int(end_port.get()), output_text)).start()
        ).grid(row=4, column=0, columnspan=2, pady=5)

        # Chat Frame
        chat_frame = ttk.LabelFrame(root, text="Encrypted Chat")
        chat_frame.pack(padx=10, pady=5, fill="both", expand=True)

        status_label = ttk.Label(chat_frame, text="Server not running")
        status_label.grid(row=0, column=0, columnspan=3, pady=5)

        chat_display = tk.Text(chat_frame, height=15, width=70, bg="#e0e0e0", font=("Helvetica", 10))
        chat_display.grid(row=1, column=0, columnspan=3, padx=5, pady=5)
        chat_display.tag_config("received", foreground="blue")
        chat_display.tag_config("sent", foreground="green")
        chat_display.tag_config("error", foreground="red")

        ttk.Label(chat_frame, text="Server Host:").grid(row=2, column=0, padx=5, pady=5)
        chat_host = ttk.Entry(chat_frame)
        chat_host.grid(row=2, column=1, padx=5, pady=5)
        chat_host.insert(0, "0.0.0.0")

        ttk.Label(chat_frame, text="Port:").grid(row=2, column=2, padx=5, pady=5)
        chat_port = ttk.Entry(chat_frame)
        chat_port.grid(row=2, column=3, padx=5, pady=5)
        chat_port.insert(0, "8888")

        ttk.Button(chat_frame, text="Start Server", command=lambda: threading.Thread(
            target=self.encrypted_chat_server, args=(chat_host.get(), int(chat_port.get()), status_label, chat_display)).start()
        ).grid(row=3, column=0, pady=5)
        ttk.Button(chat_frame, text="Stop Server", command=lambda: [setattr(self, 'gui_running', False), self.server.close(), status_label.config(text="Server stopped")]).grid(row=3, column=1, pady=5)

        # Remote Connection
        ttk.Label(chat_frame, text="Remote Number:").grid(row=4, column=0, padx=5, pady=5)
        remote_number = ttk.Entry(chat_frame)
        remote_number.grid(row=4, column=1, padx=5, pady=5)

        ttk.Label(chat_frame, text="Message:").grid(row=5, column=0, padx=5, pady=5)
        message_entry = ttk.Entry(chat_frame, width=40)
        message_entry.grid(row=5, column=1, columnspan=2, padx=5, pady=5)

        ttk.Button(chat_frame, text="Send via Google Voice", command=lambda: threading.Thread(
            target=self.connect_to_google_voice, args=(remote_number.get(), message_entry.get(), chat_display)).start()
        ).grid(row=6, column=0, pady=5)
        ttk.Button(chat_frame, text="Send via Signal", command=lambda: threading.Thread(
            target=self.connect_to_signal, args=(remote_number.get(), message_entry.get(), chat_display)).start()
        ).grid(row=6, column=1, pady=5)

        # Vanish Mode
        vanish_var = tk.BooleanVar()
        ttk.Checkbutton(chat_frame, text="Vanish Mode (Hex)", variable=vanish_var, command=lambda: setattr(self, 'vanish_mode', vanish_var.get())).grid(row=7, column=0, pady=5)

        def decode_hex():
            selected = chat_display.get("sel.first", "sel.last")
            try:
                decoded = bytes.fromhex(selected).decode('utf-8')
                chat_display.insert(tk.END, f"Decoded: {decoded}\n", "sent")
            except Exception as e:
                chat_display.insert(tk.END, f"Decode error: {e}\n", "error")

        ttk.Button(chat_frame, text="Decode Selected Hex", command=decode_hex).grid(row=7, column=1, pady=5)

        root.protocol("WM_DELETE_WINDOW", lambda: [setattr(self, 'gui_running', False), root.destroy()])
        root.mainloop()

def main():
    parser = argparse.ArgumentParser(description="Secure Port Scanner and Encrypted Chat Server")
    parser.add_argument('--chat', action='store_true', help="Start the encrypted chat server")
    parser.add_argument('--scan', action='store_true', help="Perform a port scan")
    parser.add_argument('--go-dummy-mode', action='store_true', help="Run in GUI mode")
    parser.add_argument('--host', type=str, default='localhost', help="Host to scan or bind server")
    parser.add_argument('--start-port', type=int, default=1, help="Start port for scanning")
    parser.add_argument('--end-port', type=int, default=65535, help="End port for scanning")
    args = parser.parse_args()

    scanner = SecurePortScanner()
    user_id, secret, hashed_secret = scanner.generate_user_credentials()
    logger.info(f"Generated credentials - User ID: {user_id}, Secret: {secret}")

    if args.go_dummy_mode:
        scanner.run_gui()
    elif args.chat:
        scanner.encrypted_chat_server(host=args.host)
    elif args.scan:
        results = scanner.port_scan(args.host, args.start_port, args.end_port)
        for port, is_open in results.items():
            status = "open" if is_open else "closed"
            logger.info(f"Port {port} is {status}")
    else:
        print("Please specify --chat, --scan, or --go-dummy-mode")
        parser.print_help()

def install():
    scanner = SecurePortScanner()
    data = "Initial configuration data"
    encrypted_data = scanner.public_key.encrypt(
        data.encode(),
        padding=None  # Note: In production, use OAEP padding
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
