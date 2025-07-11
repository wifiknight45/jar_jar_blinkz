# jar_jar_blinkz
A Python script that provides multi-threaded port scanning &amp; an encrypted telnet chat server using ECC (521-bit), SHA-2/SHA-3, with automatic one-time user credential generation and an hourly rotating, password protected encrypted changelog, designed for use on live USB systems. 
# Secure Port Scanner and Chat API

# reaperUp enhancements - currently under development
Updates and Enhancements Overview
Below is a breakdown of the major changes made to the original script to produce the headless, Google Colab–compatible version with robust error handling and three rounds of debugging.

1. GUI Removal and Headless Operation
All tkinter and ttk imports, widgets, and event loops have been removed.

Replaced interactive GUI elements with console output (print and structured logs).

Eliminated the run_gui, _start_key_rotation(option), and all GUI-specific callbacks.

2. Google Colab Compatibility
Switched hardware-specific dependencies (e.g., pigpio, spidev, NeoPixel) out—none are required for headless operation.

Ensured pure-Python standard libraries plus cryptography, Twilio, and signal_protocol can install in Colab via pip.

Removed any code paths that rely on local file dialogs or interactive windows.

3. Enhanced Error Handling
Wrapped every major I/O, network, threading, cryptography, and SMTP operation in try/except.

Logged and printed clear error messages on failure.

In critical initialization errors, re-raised exceptions after logging to prevent silent failures.

Added timeouts and safe shutdown in network servers.

4. Logging Improvements
Configured a named logger (phantom_reaperr) with both file and console handlers.

Standardized log format (timestamp – level – message) in secure_scanner.log.

Emitted INFO, WARNING, and CRITICAL levels as appropriate.

Console handler uses a simplified format for immediate feedback.

5. Command-Line Interface Refactor
Replaced custom argparse flags and GUI toggles with subcommands:

scan – port scanning

chat – encrypted chat server

sms – Twilio SMS sender

email– encrypted email via SMTP

Each subparser validates its required arguments.

Centralized dispatch in main() to invoke the correct method headlessly.

6. Security and Cryptography Updates
Maintained RSA identity keys and Signal Protocol integration.

Kept ECC key rotation but moved to a background daemon thread with configurable interval.

Strengthened KDF (PBKDF2HMAC) parameters for email encryption.

Ensured AES-CFB IV usage and base64 encoding for safe transport.

7. Debugging Adjustments
Verified port-scan threading logic to avoid race conditions and ensured sorted output.

Confirmed chat server cleanly closes sockets on exceptions and continues accepting new clients.

Tested Twilio and SMTP paths with missing credentials to raise comprehensible errors.

Simulated vanish-mode message display and echo loop to ensure correctness.

This is a Python-based tool that combines port scanning and encrypted chat functionality with strong security features.

## Features
- **Port Scanning**: Scans a range of ports on a target host using multiple threads.
- **Encrypted Chat**: Runs a secure telnet-style chat server with ECC encryption.
- **Security**: Uses 521-bit ECC, SHA-512, SHA-3, and AES encryption.
- **User Accounts**: Automatically generates unique one-time usernames and passwords.
- **Changelog**: Keeps an encrypted log of activities with a 20-character password that changes hourly.
- **Portable**: Works on live USB systems and through SSH/bash.

## Requirements
- Python 3.x
- `cryptography` library (`pip install cryptography`)
- Root privileges for scanning ports below 1024

## Installation
1. Save the script as `scanner.py`.
2. Make it executable:
   ```bash
   chmod +x scanner.py
   ```
3. Install the required library:
   ```bash
   pip install cryptography
   ```

## Usage
Run the script from the command line with these options:

### Port Scanning
Scan ports on a target host:
```bash
sudo ./scanner.py --host <target_ip> --start-port <start> --end-port <end>
```
- Example: `sudo ./scanner.py --host 192.168.1.1 --start-port 1 --end-port 1000`

### Chat Server
Start the encrypted chat server:
```bash
./scanner.py --chat
```
- Default host: `0.0.0.0`, port: `8888`

### Over SSH
Run remotely via SSH:
```bash
ssh user@remote "bash -c './scanner.py --host localhost'"
```

## Output
- **Credentials**: On startup, it generates and displays a unique username and password.
- **Port Scan**: Lists open ports found on the target.
- **Chat**: Runs a server and shows messages from connected clients.
- **Changelog**: Stores encrypted scan results in memory (lost on reboot).

## Notes
- Use `sudo` for full port scanning capabilities.
- The chat server requires a compatible client with matching encryption.
- The changelog is encrypted and only stored in memory, making it ideal for live USB use.
- Ctrl+C to stop the script.

## Security Details
- **Encryption**: 521-bit ECC for key exchange, AES for messages and changelog.
- **Hashing**: SHA-3 for passwords, SHA-512 for key derivation.
- **Key Rotation**: Changelog password changes every hour.

## Update
Error Handling: Specific exception handling, logging, and potential retry mechanisms are added.
Signal Protocol Chat: handle_client is updated to use Signal Protocol for encryption.
Encrypted Installation: The install function handles encryption and persistence.
Installation Check: The script checks for the presence of the encrypted configuration file to determine if it's already installed.
