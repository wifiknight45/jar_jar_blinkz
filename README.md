# jar_jar_blinkz
A Python script that provides multi-threaded port scanning &amp; an encrypted telnet chat server using ECC (521-bit), SHA-2/SHA-3, with automatic one-time user credential generation and an hourly rotating, password protected encrypted changelog, designed for use on live USB systems. 
# Secure Port Scanner and Chat API

This is a Python-based tool that combines port scanning and encrypted chat functionality with strong security features, designed to run on a live USB system.

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

## update
Error Handling: Specific exception handling, logging, and potential retry mechanisms are added.
Signal Protocol Chat: handle_client is updated to use Signal Protocol for encryption.
Encrypted Installation: The install function handles encryption and persistence.
Installation Check: The script checks for the presence of the encrypted configuration file to determine if it's already installed.
