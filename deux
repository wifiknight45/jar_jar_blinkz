'''change to fix sterilization error:'''

def handle_client(self, client, addr):
    """Handle chat client connection"""
    from cryptography.hazmat.primitives import serialization  # Add this import

    # Exchange public keys
    client.send(self.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP521R1(),
        client.recv(1024)
    )
    # ... (rest of the handle_client method) ...

      --------------
""""update with error fix applied:"""
      
#!/usr/bin/env python3

import argparse
import socket
import threading
import time
import os
import hashlib
import secrets
from cryptography.hazmat.primitives import hashes, serialization # Import serialization here
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import uuid

class SecurePortScanner:
    def __init__(self):
        # ... (rest of the __init__ method remains the same) ...

    # ... (other methods remain the same) ...

    def handle_client(self, client, addr):
        """Handle chat client connection"""
        # Exchange public keys  (serialization is now available)
        client.send(self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP521R1(),
            client.recv(1024)
        )
