# TCP Network Scanner

This script is a TCP port scanner built using Python. It leverages the `python-nmap` module (a Python wrapper for the Nmap tool) to:

- Scan a target host for open TCP ports
- Identify the services running on these ports
- Optionally display filtered or closed ports in verbose mode

## Usage

Run the script with:

```bash
python network_scanner_personal.py -H <host> -p <ports> -v
Requirements

    Python 3.x

    python-nmap package (install via pip install python-nmap)

    Nmap installed on the system
