# Advanced Network Scanner

A professional-grade port scanning tool with vulnerability detection, written in Python.

## Features
- TCP Connect & SYN Stealth Scanning
- Service Fingerprinting (HTTP, SSH, FTP)
- Basic Vulnerability Checks
- Multi-threaded for performance
- Detailed Markdown Reporting

## Usage
```bash
# Basic scan
python3 scanner.py 192.168.1.1 -p 1-1000

# Stealth SYN scan (requires root)
sudo python3 scanner.py 10.0.0.0/24 -s syn

# Full vulnerability scan
python3 scanner.py example.com -p 1-65535 -o report.md
