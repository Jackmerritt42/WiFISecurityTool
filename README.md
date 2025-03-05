# Wi-Fi Security Assessment Tool

A portable tool for analyzing the security of nearby Wi-Fi networks. This tool is designed to run on both Windows and Linux/Raspberry Pi systems, making it ideal for security audits, network assessments, and educational purposes.

## Features

- **Multi-platform support**: Works on Windows, Linux, and Raspberry Pi
- **Comprehensive Wi-Fi scanning**: Detects SSIDs, encryption types, signal strength, and MAC addresses
- **Security analysis**: Identifies vulnerabilities and provides remediation recommendations
- **Monitor mode support**: Enhanced scanning capabilities on Linux/Raspberry Pi (requires compatible hardware)
- **Continuous scanning**: Option to perform repeated scans at specified intervals
- **Detailed reporting**: Generate reports in TXT and JSON formats
- **Colorized output**: Easy-to-read terminal output with risk-based color coding

## Prerequisites

### Windows
- Python 3.7 or higher
- Administrative privileges for network scanning

### Linux/Raspberry Pi
- Python 3.7 or higher
- Required packages:
  ```
  sudo apt update
  sudo apt install wireless-tools iw iproute2 python3-pip
  ```

- For advanced monitor mode features:
  ```
  sudo apt install aircrack-ng
  ```

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/Jackmerritt42/WiFiSecurityTool.git
   cd WiFiSecurityTool
   ```

2. Install required Python packages:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Basic Scanning

```bash
# Windows
python src/main.py -s -v

# Linux/Raspberry Pi
python src/main.py -s -i wlan0 -v
```

### Generate Security Report

```bash
python src/main.py -s -o reports/wifi_report.txt
```

### Use Monitor Mode (Linux/RPi only)

```bash
sudo python src/main.py -s -i wlan0 -m -v
```

### Continuous Scanning

```bash
python src/main.py -s -i wlan0 -c 60 -v
```
This runs a scan every 60 seconds until interrupted (Ctrl+C).

### Full Command Reference

```
usage: main.py [-h] [-s] [-i INTERFACE] [-o OUTPUT] [-f {txt,json}] [-m]
               [-c SECONDS] [-v]

Wi-Fi Security Assessment Tool

optional arguments:
  -h, --help            show this help message and exit
  -s, --scan            Scan for nearby networks
  -i INTERFACE, --interface INTERFACE
                        Wireless interface to use (Linux only)
  -o OUTPUT, --output OUTPUT
                        Output report file
  -f {txt,json}, --format {txt,json}
                        Report format
  -m, --monitor         Enable monitor mode (Linux only)
  -c SECONDS, --continuous SECONDS
                        Continuously scan every SECONDS
  -v, --verbose         Enable verbose output

Example: python main.py -s -i wlan0 -o reports/wifi_report.txt
```

## Raspberry Pi Setup

For portable scanning with a Raspberry Pi:

1. Install Raspberry Pi OS (formerly Raspbian)
2. Install required dependencies
3. Clone the repository
4. Connect a compatible Wi-Fi adapter if enhanced features are needed
5. Run with appropriate privileges

### Auto-start on Boot (Optional)

Create a systemd service file:

```bash
sudo nano /etc/systemd/system/wifi-scanner.service
```

With the following content:

```
[Unit]
Description=Wi-Fi Security Scanner
After=network.target

[Service]
ExecStart=/usr/bin/python3 /home/pi/WiFiSecurityTool/src/main.py -s -i wlan0 -c 300 -o /home/pi/WiFiSecurityTool/reports/scan_%H%M%S.txt
User=root
WorkingDirectory=/home/pi/WiFiSecurityTool
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl enable wifi-scanner.service
sudo systemctl start wifi-scanner.service
```

## Security and Legal Considerations

- Only scan networks you own or have explicit permission to test
- Some scanning techniques may be illegal in certain jurisdictions
- The tool is designed for educational and security audit purposes only
- The authors are not responsible for misuse of this tool

## Authors

- Jack Merritt
- Thomas Busick

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- University of Cincinnati Cybersecurity program
- Open-source wireless security tools and communities
