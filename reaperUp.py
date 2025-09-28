#!/usr/bin/env python3
"""
phantom_reaperr.py

A headless, Colab-compatible secure port scanner, encrypted chat server,
SMS sender via Twilio, and encrypted email sender via SMTP (e.g., ProtonMail Bridge).

Usage Examples:

  # Port scan
  python phantom_reapaperr.py scan \
    --host 192.168.1.1 --start 1 --end 1024

  # Run encrypted chat server
  python phantom_reaperr.py chat \
    --host 0.0.0.0 --port 8888 \
    [--vanish] [--rotate-interval 300]

  # Send SMS via Twilio
  python phantom_reaperr.py sms \
    --to +15551234567 --msg "Hello" \
    [--sid YOUR_SID --token YOUR_TOKEN --from-number +15557654321]

  # Send encrypted email
  python phantom_reaperr.py email \
    --to user@example.com --subject "Secret" --body "Top secret" \
    [--smtp-host 127.0.0.1 --smtp-port 1025 \
     --user you@protonmail.com --pass your_bridge_password \
     --from you@protonmail.com]
"""

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
import smtplib
from email.mime.text import MIMEText

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

# ─────────────────────────────────────────────────────────────────────────────
# Logging Configuration
# ─────────────────────────────────────────────────────────────────────────────
logger = logging.getLogger("phantom_reaperr")
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler("secure_scanner.log")
file_handler.setFormatter(logging.Formatter(
    "%(asctime)s - %(levelname)s - %(message)s"
))
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(
    "%(levelname)s: %(message)s"
))
logger.addHandler(file_handler)
logger.addHandler(console_handler)


class SecurePortScanner:
    def __init__(self, vanish_mode=False, rotation_interval=None):
        try:
            # RSA identity key pair
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()

            # Signal Protocol store & sessions
            self.signal_store = InMemorySignalProtocolStore(
                generate_identity_key_pair(),
                generate_registration_id()
            )
            self.sessions = {}
            self._initialize_signal_keys()

            # Ephemeral ECC keys & vanish mode
            self.vanish_mode = vanish_mode
            self.ecc_keys = self._generate_ecc_keys()

            # Optional key rotation
            self.rotation_interval = rotation_interval
            if rotation_interval:
                self._start_key_rotation()
        except Exception as e:
            logger.critical(f"Initialization failed: {e}")
            raise

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

    # ─────────────────────────────────────────────────────────────────────────
    # Port Scanning
    # ─────────────────────────────────────────────────────────────────────────
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
        for p in range(start_port, end_port + 1):
            t = threading.Thread(
                target=lambda port=p: results.update([self.scan_port(host, port)])
            )
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        for port, is_open in sorted(results.items()):
            status = "open" if is_open else "closed"
            print(f"{host}:{port} → {status}")
        return results

    # ─────────────────────────────────────────────────────────────────────────
    # Encrypted Chat Server
    # ─────────────────────────────────────────────────────────────────────────
    def encrypted_chat_server(self, host, port):
        logger.info(f"Starting chat server on {host}:{port}")
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

    # ─────────────────────────────────────────────────────────────────────────
    # Twilio SMS
    # ─────────────────────────────────────────────────────────────────────────
    def send_sms(self, to_number, message,
                 sid=None, token=None, from_number=None):
        try:
            sid = sid or os.getenv("TWILIO_SID")
            token = token or os.getenv("TWILIO_TOKEN")
            frm = from_number or os.getenv("TWILIO_FROM")
            if not all([sid, token, frm]):
                raise ValueError("Missing Twilio SID, token, or from-number")

            client = Client(sid, token)
            client.messages.create(body=message, from_=frm, to=to_number)
            logger.info(f"Sent SMS to {to_number}")
        except Exception as e:
            logger.error(f"SMS send failed: {e}")
            print(f"Error sending SMS: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # ProtonMail-Bridge Encrypted Email
    # ─────────────────────────────────────────────────────────────────────────
    def encrypt_email(self, message):
        try:
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
        except Exception as e:
            logger.error(f"Email encryption error: {e}")
            raise

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
        except Exception as e:
            logger.error(f"Email send failed: {e}")
            print(f"Error sending encrypted email: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Headless Secure Scanner & Communication Tool"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # Port scan subcommand
    p_scan = sub.add_parser("scan", help="Port scan a host range")
    p_scan.add_argument("--host", required=True)
    p_scan.add_argument("--start", type=int, required=True)
    p_scan.add_argument("--end", type=int, required=True)

    # Chat server subcommand
    p_chat = sub.add_parser("chat", help="Run encrypted chat server")
    p_chat.add_argument("--host", default="0.0.0.0")
    p_chat.add_argument("--port", type=int, default=8888)
    p_chat.add_argument("--vanish", action="store_true",
                        help="Display incoming messages in hex")
    p_chat.add_argument("--rotate-interval", type=int,
                        help="Seconds between ECC key rotations")

    # SMS subcommand
    p_sms = sub.add_parser("sms", help="Send SMS via Twilio")
    p_sms.add_argument("--to", required=True)
    p_sms.add_argument("--msg", required=True)
    p_sms.add_argument("--sid")
    p_sms.add_argument("--token")
    p_sms.add_argument("--from-number")

    # Email subcommand
    p_email = sub.add_parser("email", help="Send encrypted email")
    p_email.add_argument("--to", required=True)
    p_email.add_argument("--subject", required=True)
    p_email.add_argument("--body", required=True)
    p_email.add_argument("--smtp-host", default="127.0.0.1")
    p_email.add_argument("--smtp-port", type=int, default=1025)
    p_email.add_argument("--user", required=True,
                         help="SMTP username (ProtonMail Bridge)")
    p_email.add_argument("--pass", dest="password", required=True,
                         help="SMTP password (ProtonMail Bridge)")
    p_email.add_argument("--from", dest="from_email", required=True,
                         help="Sender email address")

    args = parser.parse_args()

    try:
        tool = SecurePortScanner(
            vanish_mode=getattr(args, "vanish", False),
            rotation_interval=getattr(args, "rotate_interval", None)
        )

        if args.cmd == "scan":
            tool.port_scan(args.host, args.start, args.end)

        elif args.cmd == "chat":
            tool.encrypted_chat_server(args.host, args.port)

        elif args.cmd == "sms":
            tool.send_sms(
                args.to, args.msg,
                sid=args.sid, token=args.token,
                from_number=args.from_number
            )

        elif args.cmd == "email":
            tool.send_encrypted_email(
                args.to, args.subject, args.body,
                smtp_host=args.smtp_host,
                smtp_port=args.smtp_port,
                user=args.user, password=args.password,
                from_email=args.from_email
            )

    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        print(f"Fatal error: {e}")


if __name__ == "__main__":
    main()
```
