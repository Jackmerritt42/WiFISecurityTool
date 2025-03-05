#!/usr/bin/env python3
# Wi-Fi network scanner module with Raspberry Pi support
# Authors: Jack Merritt and Thomas Busick

import subprocess
import re
import platform
import os
import json
import time
from datetime import datetime

class WiFiScanner:
    """Scanner for Wi-Fi networks with support for Windows, Linux, and Raspberry Pi"""
    
    def __init__(self, interface="wlan0", verbose=False):
        """Initialize the scanner
        
        Args:
            interface (str): Network interface to use for scanning (Linux/Raspberry Pi only)
            verbose (bool): Whether to show verbose output
        """
        self.verbose = verbose
        self.interface = interface
        self.os_type = platform.system()  # Windows, Linux, Darwin (macOS)
        
        if self.verbose:
            print(f'[INFO] Initializing scanner on {self.os_type}')
            if self.os_type == 'Linux':
                print(f'[INFO] Using interface: {self.interface}')
    
    def _log(self, level, message):
        """Log a message if verbose mode is enabled"""
        if self.verbose or level != 'INFO':
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f'[{timestamp}] [{level}] {message}')
    
    def scan(self):
        """Scan for nearby Wi-Fi networks
        
        Returns:
            list: List of dictionaries containing network information
        """
        self._log('INFO', 'Starting network scan')
        
        if self.os_type == 'Windows':
            return self._scan_windows()
        elif self.os_type == 'Linux':
            return self._scan_linux()
        else:
            self._log('ERROR', f'Unsupported operating system: {self.os_type}')
            return []
    
    def _scan_windows(self):
        """Scan for networks on Windows using netsh"""
        networks = []
        
        try:
            # Check if running as administrator
            if not self._is_admin():
                self._log('WARNING', 'This script may require administrator privileges for full functionality')
            
            # Run netsh command to get network info
            self._log('INFO', 'Running netsh command')
            
            output = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], 
                universal_newlines=True
            )
            
            # Split the output by network
            network_blocks = re.split(r'SSID \d+ : ', output)[1:]
            
            for block in network_blocks:
                network = {}
                
                # Extract network name (SSID)
                ssid_line = block.split('\n')[0].strip()
                network['ssid'] = ssid_line
                
                # Extract network type
                network_type_match = re.search(r'Network type\s+: (.+)', block)
                if network_type_match:
                    network['network_type'] = network_type_match.group(1).strip()
                
                # Extract authentication type (encryption)
                auth_match = re.search(r'Authentication\s+: (.+)', block)
                if auth_match:
                    auth_type = auth_match.group(1).strip()
                    network['authentication'] = auth_type
                    
                    # Determine encryption type based on authentication
                    if auth_type == 'Open':
                        network['encryption'] = 'OPEN'
                    elif auth_type == 'WEP':
                        network['encryption'] = 'WEP'
                    elif 'WPA2' in auth_type:
                        network['encryption'] = 'WPA2'
                    elif 'WPA3' in auth_type:
                        network['encryption'] = 'WPA3'
                    elif 'WPA' in auth_type:
                        network['encryption'] = 'WPA'
                    else:
                        network['encryption'] = 'UNKNOWN'
                
                # Extract encryption type
                encryption_match = re.search(r'Encryption\s+: (.+)', block)
                if encryption_match:
                    network['cipher'] = encryption_match.group(1).strip()
                
                # Extract BSSIDs and signal strength
                bssids = []
                bssid_blocks = re.findall(r'BSSID \d+\s+: (.+)(?:\n.+)+?Signal\s+: (\d+)%', block)
                
                for bssid_match in bssid_blocks:
                    bssid = bssid_match[0].strip()
                    signal = int(bssid_match[1].strip())
                    bssids.append({
                        'bssid': bssid,
                        'signal': signal
                    })
                
                network['bssids'] = bssids
                
                # Set the strongest signal as the network signal
                if bssids:
                    network['signal'] = max(bssid['signal'] for bssid in bssids)
                
                # Add security risk level based on encryption
                network['security_risk'] = self._assess_security_risk(network)
                
                # Add vulnerability checks
                network['vulnerabilities'] = self._check_vulnerabilities(network)
                
                networks.append(network)
            
            self._log('INFO', f'Found {len(networks)} networks')
            
        except subprocess.CalledProcessError as e:
            self._log('ERROR', f'Error running netsh command: {str(e)}')
        except Exception as e:
            self._log('ERROR', f'Unexpected error during Windows scan: {str(e)}')
            
        return networks
    
    def _scan_linux(self):
        """Scan for networks on Linux/Raspberry Pi using iwlist"""
        networks = []
        
        try:
            # Check if running as root
            if not self._is_admin():
                self._log('WARNING', 'This script requires root privileges for full functionality on Linux')
            
            # Run iwlist scan command
            self._log('INFO', f'Running iwlist scan on {self.interface}')
            
            try:
                output = subprocess.check_output(
                    ['sudo', 'iwlist', self.interface, 'scan'], 
                    universal_newlines=True,
                    stderr=subprocess.STDOUT
                )
            except subprocess.CalledProcessError as e:
                # Try alternative method with iw
                self._log('WARNING', f'iwlist failed, trying iw command: {e}')
                output = subprocess.check_output(
                    ['sudo', 'iw', 'dev', self.interface, 'scan'], 
                    universal_newlines=True,
                    stderr=subprocess.STDOUT
                )
            
            # Split output into cells (networks)
            cells = output.split('Cell ')[1:]
            if not cells and 'BSS' in output:
                # Handle iw output format
                cells = output.split('BSS ')[1:]
            
            for cell in cells:
                network = {}
                
                # Extract MAC address (BSSID)
                mac_match = re.search(r'([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})', cell, re.IGNORECASE)
                if mac_match:
                    mac = mac_match.group(1).upper()
                    network['bssids'] = [{'bssid': mac, 'signal': 0}]  # Signal will be updated below
                
                # Extract SSID
                ssid_match = re.search(r'ESSID:"([^"]*)"', cell)
                if not ssid_match:
                    # Try iw format
                    ssid_match = re.search(r'SSID: ([^\n]*)', cell)
                
                if ssid_match:
                    network['ssid'] = ssid_match.group(1).strip()
                else:
                    network['ssid'] = '<Hidden Network>'
                
                # Extract signal strength
                signal_match = re.search(r'Signal level=(-?\d+) dBm', cell)
                if not signal_match:
                    # Try alternative format
                    signal_match = re.search(r'signal: (-?\d+)', cell)
                
                if signal_match:
                    # Convert dBm to percentage (approximate)
                    # dBm range is typically -100 (weak) to -30 (strong)
                    dbm = int(signal_match.group(1))
                    signal_percent = min(100, max(0, int((dbm + 100) * 2)))
                    network['signal'] = signal_percent
                    
                    # Update the BSSID signal if it exists
                    if 'bssids' in network and network['bssids']:
                        network['bssids'][0]['signal'] = signal_percent
                
                # Extract encryption information
                if 'key:on' in cell or 'capability: Privacy' in cell:
                    # Determine encryption type
                    if 'WPA3' in cell:
                        network['encryption'] = 'WPA3'
                    elif 'WPA2' in cell:
                        network['encryption'] = 'WPA2'
                    elif 'WPA' in cell:
                        network['encryption'] = 'WPA'
                    elif 'WEP' in cell:
                        network['encryption'] = 'WEP'
                    else:
                        network['encryption'] = 'UNKNOWN'
                else:
                    network['encryption'] = 'OPEN'
                
                # Extract cipher information
                cipher_match = re.search(r'Group Cipher\s*:\s*([^\n]*)', cell)
                if cipher_match:
                    network['cipher'] = cipher_match.group(1).strip()
                
                # Check for WPS support
                network['wps_enabled'] = 'WPS' in cell
                
                # Extract channel
                channel_match = re.search(r'Channel:(\d+)', cell)
                if not channel_match:
                    # Try frequency and convert to channel
                    freq_match = re.search(r'freq: (\d+)', cell)
                    if freq_match:
                        freq = int(freq_match.group(1))
                        # Approximate channel from frequency
                        if freq >= 2412 and freq <= 2484:
                            channel = int((freq - 2412) / 5) + 1
                            if freq == 2484:
                                channel = 14
                        elif freq >= 5170 and freq <= 5825:
                            channel = int((freq - 5170) / 5) + 34
                        else:
                            channel = 0
                        network['channel'] = channel
                else:
                    network['channel'] = int(channel_match.group(1))
                
                # Add security risk level based on encryption
                network['security_risk'] = self._assess_security_risk(network)
                
                # Add vulnerability checks
                network['vulnerabilities'] = self._check_vulnerabilities(network)
                
                networks.append(network)
            
            self._log('INFO', f'Found {len(networks)} networks')
            
        except subprocess.CalledProcessError as e:
            self._log('ERROR', f'Error scanning networks: {e.output if hasattr(e, "output") else str(e)}')
            self._log('INFO', 'Make sure you have the necessary permissions and wifi tools installed')
        except Exception as e:
            self._log('ERROR', f'Unexpected error during Linux scan: {str(e)}')
        
        return networks
    
    def _is_admin(self):
        """Check if the script is running with admin/root privileges"""
        try:
            return os.geteuid() == 0  # Unix-based systems
        except AttributeError:
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0  # Windows
            except:
                return False  # Default to False if cannot determine
    
    def _assess_security_risk(self, network):
        """Assess the security risk of a network based on its encryption"""
        encryption = network.get('encryption', 'UNKNOWN')
        
        if encryption == 'OPEN':
            return 'HIGH'
        elif encryption == 'WEP':
            return 'HIGH'
        elif encryption == 'WPA':
            return 'MEDIUM'
        elif encryption == 'WPA2':
            cipher = network.get('cipher', '')
            if 'TKIP' in cipher:
                return 'MEDIUM'
            return 'LOW'
        elif encryption == 'WPA3':
            return 'VERY LOW'
        else:
            return 'UNKNOWN'
    
    def _check_vulnerabilities(self, network):
        """Check for vulnerabilities in the network"""
        vulnerabilities = []
        encryption = network.get('encryption', 'UNKNOWN')
        
        # Check for open networks
        if encryption == 'OPEN':
            vulnerabilities.append({
                'type': 'NO_ENCRYPTION',
                'description': 'Network has no encryption',
                'recommendation': 'Implement WPA2 or WPA3 encryption',
                'severity': 'HIGH'
            })
        
        # Check for WEP encryption
        elif encryption == 'WEP':
            vulnerabilities.append({
                'type': 'WEAK_ENCRYPTION',
                'description': 'WEP encryption is easily broken using freely available tools',
                'recommendation': 'Upgrade to WPA2 or WPA3 encryption',
                'severity': 'HIGH'
            })
        
        # Check for WPA encryption
        elif encryption == 'WPA':
            vulnerabilities.append({
                'type': 'OUTDATED_ENCRYPTION',
                'description': 'WPA encryption is vulnerable to various attacks',
                'recommendation': 'Upgrade to WPA2 or WPA3 encryption',
                'severity': 'MEDIUM'
            })
        
        # Check for WPA2 with TKIP
        elif encryption == 'WPA2' and 'TKIP' in network.get('cipher', ''):
            vulnerabilities.append({
                'type': 'WEAK_CIPHER',
                'description': 'WPA2 with TKIP cipher is less secure than CCMP/AES',
                'recommendation': 'Configure router to use WPA2 with AES/CCMP only',
                'severity': 'MEDIUM'
            })
        
        # Check for WPS
        if network.get('wps_enabled', False):
            vulnerabilities.append({
                'type': 'WPS_ENABLED',
                'description': 'Wi-Fi Protected Setup (WPS) may be vulnerable to brute force attacks',
                'recommendation': 'Disable WPS or ensure router firmware is up to date',
                'severity': 'MEDIUM'
            })
        
        return vulnerabilities

    def get_interface_list(self):
        """Get list of available wireless interfaces
        
        Returns:
            list: List of wireless interface names
        """
        interfaces = []
        
        try:
            if self.os_type == 'Linux':
                # Try using iw to list wireless interfaces
                output = subprocess.check_output(
                    ['iw', 'dev'], 
                    universal_newlines=True
                )
                
                # Parse the output to extract interface names
                for line in output.split('\n'):
                    if 'Interface' in line:
                        interface = line.split('Interface')[1].strip()
                        interfaces.append(interface)
            
            elif self.os_type == 'Windows':
                # Use netsh to list wireless interfaces
                output = subprocess.check_output(
                    ['netsh', 'wlan', 'show', 'interfaces'], 
                    universal_newlines=True
                )
                
                # Parse the output to extract interface names
                interface_blocks = output.split('\n\n')
                for block in interface_blocks:
                    if 'Name' in block:
                        name_match = re.search(r'Name\s+: (.+)', block)
                        if name_match:
                            interfaces.append(name_match.group(1).strip())
        
        except Exception as e:
            self._log('ERROR', f'Error getting wireless interfaces: {str(e)}')
        
        return interfaces

    def enable_monitor_mode(self):
        """Enable monitor mode on the wireless interface (Linux/Raspberry Pi only)
        
        Returns:
            bool: True if successful, False otherwise
        """
        if self.os_type != 'Linux':
            self._log('ERROR', 'Monitor mode is only supported on Linux/Raspberry Pi')
            return False
        
        try:
            # Check if running as root
            if not self._is_admin():
                self._log('ERROR', 'Root privileges required to enable monitor mode')
                return False
            
            # Check if airmon-ng is available
            try:
                subprocess.check_output(['which', 'airmon-ng'], universal_newlines=True)
                use_airmon = True
            except:
                use_airmon = False
            
            if use_airmon:
                # Use airmon-ng to enable monitor mode
                self._log('INFO', f'Enabling monitor mode on {self.interface} using airmon-ng')
                
                # Kill processes that might interfere
                subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.PIPE)
                
                # Start monitor mode
                output = subprocess.check_output(
                    ['airmon-ng', 'start', self.interface], 
                    universal_newlines=True
                )
                
                # Parse the output to get the monitor interface name
                monitor_if_match = re.search(r'(mon\d+|wlan\d+mon)', output)
                if monitor_if_match:
                    self.interface = monitor_if_match.group(0)
                    self._log('INFO', f'Monitor mode enabled on {self.interface}')
                    return True
                else:
                    # Check if the interface name simply has 'mon' appended
                    self.interface = f"{self.interface}mon"
                    # Verify the interface exists
                    if self.interface in self.get_interface_list():
                        self._log('INFO', f'Monitor mode enabled on {self.interface}')
                        return True
            else:
                # Use iw to enable monitor mode
                self._log('INFO', f'Enabling monitor mode on {self.interface} using iw')
                
                # Bring the interface down
                subprocess.run(['ip', 'link', 'set', self.interface, 'down'], stdout=subprocess.PIPE)
                
                # Set monitor mode
                subprocess.run(['iw', 'dev', self.interface, 'set', 'monitor', 'none'], stdout=subprocess.PIPE)
                
                # Bring the interface back up
                subprocess.run(['ip', 'link', 'set', self.interface, 'up'], stdout=subprocess.PIPE)
                
                # Verify monitor mode is enabled
                output = subprocess.check_output(
                    ['iw', 'dev', self.interface, 'info'], 
                    universal_newlines=True
                )
                
                if 'type monitor' in output:
                    self._log('INFO', f'Monitor mode enabled on {self.interface}')
                    return True
            
            self._log('ERROR', 'Failed to enable monitor mode')
            return False
            
        except Exception as e:
            self._log('ERROR', f'Error enabling monitor mode: {str(e)}')
            return False
    
    def disable_monitor_mode(self):
        """Disable monitor mode and restore normal operation (Linux/Raspberry Pi only)
        
        Returns:
            bool: True if successful, False otherwise
        """
        if self.os_type != 'Linux':
            return False
        
        try:
            # Check if airmon-ng is available
            try:
                subprocess.check_output(['which', 'airmon-ng'], universal_newlines=True)
                use_airmon = True
            except:
                use_airmon = False
            
            if use_airmon:
                # Use airmon-ng to disable monitor mode
                self._log('INFO', f'Disabling monitor mode on {self.interface}')
                subprocess.run(['airmon-ng', 'stop', self.interface], stdout=subprocess.PIPE)
                
                # Try to determine the original interface name
                if self.interface.endswith('mon'):
                    self.interface = self.interface[:-3]
                elif 'mon' in self.interface:
                    self.interface = self.interface.split('mon')[0]
            else:
                # Use iw to disable monitor mode
                self._log('INFO', f'Disabling monitor mode on {self.interface}')
                
                # Bring the interface down
                subprocess.run(['ip', 'link', 'set', self.interface, 'down'], stdout=subprocess.PIPE)
                
                # Set managed mode
                subprocess.run(['iw', 'dev', self.interface, 'set', 'type', 'managed'], stdout=subprocess.PIPE)
                
                # Bring the interface back up
                subprocess.run(['ip', 'link', 'set', self.interface, 'up'], stdout=subprocess.PIPE)
            
            # Restart network manager to restore normal operation
            subprocess.run(['systemctl', 'restart', 'NetworkManager'], stdout=subprocess.PIPE)
            
            self._log('INFO', 'Monitor mode disabled')
            return True
            
        except Exception as e:
            self._log('ERROR', f'Error disabling monitor mode: {str(e)}')
            return False

if __name__ == '__main__':
    # Command line testing
    import argparse
    
    parser = argparse.ArgumentParser(description='Test Wi-Fi scanner functionality')
    parser.add_argument('-i', '--interface', type=str, default='wlan0', help='Wireless interface to use (Linux only)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-m', '--monitor', action='store_true', help='Enable monitor mode (Linux only)')
    
    args = parser.parse_args()
    
    # Create scanner
    scanner = WiFiScanner(interface=args.interface, verbose=args.verbose)
    
    # Enable monitor mode if requested
    if args.monitor and platform.system() == 'Linux':
        success = scanner.enable_monitor_mode()
        if not success:
            print('Failed to enable monitor mode. Running normal scan instead.')
    
    try:
        # Scan for networks
        networks = scanner.scan()
        
        # Display results
        print(f'\nFound {len(networks)} networks:')
        for i, network in enumerate(networks, 1):
            print(f"\n{i}. SSID: {network.get('ssid', 'Unknown')}")
            print(f"   Channel: {network.get('channel', 'Unknown')}")
            print(f"   Encryption: {network.get('encryption', 'Unknown')}")
            print(f"   Signal Strength: {network.get('signal', 'Unknown')}%")
            print(f"   Security Risk: {network.get('security_risk', 'Unknown')}")
            
            if network.get('bssids'):
                print(f"   MAC Address: {network['bssids'][0]['bssid']}")
            
            print("   Vulnerabilities:")
            if network.get('vulnerabilities'):
                for vuln in network['vulnerabilities']:
                    print(f"     - {vuln.get('type', 'Unknown')}: {vuln.get('description', '')}")
                    print(f"       Recommendation: {vuln.get('recommendation', '')}")
            else:
                print("     No vulnerabilities detected")
    
    finally:
        # Disable monitor mode if it was enabled
        if args.monitor and platform.system() == 'Linux':
            scanner.disable_monitor_mode()