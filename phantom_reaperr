import sys
import subprocess
import logging
import socket
import threading
import time
import os
import base64
import smtplib
from email.mime.text import MIMEText

def install_if_missing(package):
    try:
        __import__(package)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Install dependencies if missing
for pkg in ["cryptography", "twilio"]:
    install_if_missing(pkg)

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
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
from twilio.rest import Client

# Notebook-friendly logging
logger = logging.getLogger("phantom_reaperr")
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
logger.handlers = [console_handler]

class SecurePortScanner:
    def __init__(self, vanish_mode=False, rotation_interval=None):
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
        self.vanish_mode = vanish_mode
        self.ecc_keys = self._generate_ecc_keys()
        self.rotation_interval = rotation_interval
        if rotation_interval:
            self._start_key_rotation()

    def _initialize_signal_keys(self):
        pre_keys = generate_pre_keys(0, 100)
        signed_pre = generate_signed_pre_key(
            self.signal_store.get_identity_key_pair(), 1
        )
        for pk in pre_keys:
            self.signal_store.store_pre_key(pk.get_id(), pk)
        self.signal_store.store_signed_pre_key(
            signed_pre.get_id(), signed_pre
        )

    def _generate_ecc_keys(self):
        return [
            ec.generate_private_key(ec.SECT571R1(), default_backend())
            for _ in range(3)
        ]

    def _start_key_rotation(self):
        def rotator():
            logger.info("ECC key rotation thread started")
            while True:
                time.sleep(self.rotation_interval)
                self.ecc_keys = self._generate_ecc_keys()
                logger.info(f"Rotated ECC keys every {self.rotation_interval}s")
        t = threading.Thread(target=rotator, daemon=True)
        t.start()

    def scan_port(self, host, port, timeout=1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((host, port)) == 0:
                    logger.info(f"Port {port} open on {host}")
                    return port, True
                return port, False
        except Exception as e:
            logger.warning(f"{host}:{port} scan error → {e}")
            return port, False

    def port_scan(self, host, start_port, end_port):
        results = {}
        threads = []
        def scan_and_store(port):
            results[port], status = self.scan_port(host, port)
            results[port] = status
        for p in range(start_port, end_port + 1):
            t = threading.Thread(target=scan_and_store, args=(p,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Return dict for notebook usage
        return {port: ("open" if status else "closed") for port, status in results.items()}

    def send_sms(self, to_number, message,
                 sid=None, token=None, from_number=None):
        sid = sid or os.getenv("TWILIO_SID")
        token = token or os.getenv("TWILIO_TOKEN")
        frm = from_number or os.getenv("TWILIO_FROM")
        if not all([sid, token, frm]):
            logger.error("Missing Twilio SID, token, or from-number")
            return False
        try:
            client = Client(sid, token)
            client.messages.create(body=message, from_=frm, to=to_number)
            logger.info(f"Sent SMS to {to_number}")
            return True
        except Exception as e:
            logger.error(f"SMS send failed: {e}")
            return False

    def encrypt_email(self, message):
        pkt = message.encode("utf-8")
        for priv in self.ecc_keys:
            pub = priv.public_key()
            shared = priv.exchange(ec.ECDH(), pub)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=os.urandom(16),
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(shared)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv),
                            backend=default_backend())
            pkt = iv + cipher.encryptor().update(pkt) + cipher.encryptor().finalize()
        return base64.b64encode(pkt).decode()

    def send_encrypted_email(self, to_email, subject, body,
                             smtp_host, smtp_port, user, password, from_email):
        try:
            encrypted = self.encrypt_email(body)
            msg = MIMEText(encrypted)
            msg["Subject"] = subject
            msg["From"] = from_email
            msg["To"] = to_email

            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.login(user, password)
                server.send_message(msg)
            logger.info(f"Encrypted email sent to {to_email}")
            return True
        except Exception as e:
            logger.error(f"Email send failed: {e}")
            return False

    def run_chat_server(self, host="0.0.0.0", port=8888):
        # For notebook: run in background thread
        logger.info(f"Starting chat server on {host}:{port}")
        def server_thread():
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((host, port))
                server.listen(5)
                while True:
                    client, addr = server.accept()
                    client_id = f"{addr[0]}:{addr[1]}"
                    threading.Thread(
                        target=self._handle_client,
                        args=(client, client_id),
                        daemon=True
                    ).start()
            except Exception as e:
                logger.critical(f"Chat server error: {e}")
            finally:
                try:
                    server.close()
                except Exception:
                    pass
        t = threading.Thread(target=server_thread, daemon=True)
        t.start()
        logger.info("Chat server running in background thread.")
        return t  # Return thread so user can check/join if desired

    def _handle_client(self, client, client_id):
        try:
            addr = Address(client_id, 1)
            builder = SessionBuilder(self.signal_store, addr)
            init = client.recv(4096)
            if init:
                builder.process_pre_key_bundle(init)
                self.sessions[client_id] = SessionCipher(self.signal_store, addr)
                client.send(b"SESSION_ESTABLISHED")

            cipher = self.sessions.get(client_id)
            while cipher:
                data = client.recv(4096)
                if not data:
                    break
                pt = cipher.decrypt(data)
                msg = pt.decode("utf-8", errors="ignore")
                display = msg.encode().hex() if self.vanish_mode else msg
                logger.info(f"{client_id} → {display}")

                # Echo
                resp = f"Echo: {msg}".encode("utf-8")
                client.send(cipher.encrypt(resp))
        except Exception as e:
            logger.warning(f"Client {client_id} error: {e}")
        finally:
            client.close()
            self.sessions.pop(client_id, None)
