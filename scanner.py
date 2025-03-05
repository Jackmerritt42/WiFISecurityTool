#!/usr/bin/env python3
# Wi-Fi network scanner module
# Authors: Jack Merritt and Thomas Busick

import subprocess
import re
import platform
import os

class WiFiScanner:
    """Scanner for Wi-Fi networks"""
    
    def __init__(self, verbose=False):
        """Initialize the scanner"""
        self.verbose = verbose
        self.os_type = platform.system()  # Windows, Linux, Darwin (macOS)
        if verbose:
            print(f'[INFO] Initializing scanner on {self.os_type}')
        
    def scan(self):
        """Scan for nearby Wi-Fi networks
        
        Returns:
            list: List of dictionaries containing network information
        """
        if self.verbose:
            print('[INFO] Starting network scan')
        
        if self.os_type == 'Windows':
            return self._scan_windows()
        else:
            print(f'[ERROR] Unsupported operating system: {self.os_type}')
            return []
    
    def _scan_windows(self):
        """Scan for networks on Windows using netsh"""
        networks = []
        
        try:
            # Check if running as administrator
            if os.name == 'nt' and not self._is_admin():
                print('[WARNING] This script may require administrator privileges for full functionality')
            
            # Run netsh command to get network info
            if self.verbose:
                print('[INFO] Running netsh command')
            
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
            
            if self.verbose:
                print(f'[INFO] Found {len(networks)} networks')
            
        except subprocess.CalledProcessError as e:
            print(f'[ERROR] Error running netsh command: {str(e)}')
        except Exception as e:
            print(f'[ERROR] Unexpected error during Windows scan: {str(e)}')
            
        return networks
    
    def _is_admin(self):
        """Check if the script is running with admin privileges"""
        try:
            return os.getuid() == 0
        except AttributeError:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
    
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
            return 'LOW' if 'CCMP' in cipher else 'MEDIUM'
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
                'recommendation': 'Implement WPA2 or WPA3 encryption'
            })
        
        # Check for WEP encryption
        elif encryption == 'WEP':
            vulnerabilities.append({
                'type': 'WEAK_ENCRYPTION',
                'description': 'WEP encryption is easily broken using freely available tools',
                'recommendation': 'Upgrade to WPA2 or WPA3 encryption'
            })
        
        # Check for WPA encryption
        elif encryption == 'WPA':
            vulnerabilities.append({
                'type': 'OUTDATED_ENCRYPTION',
                'description': 'WPA encryption is vulnerable to various attacks',
                'recommendation': 'Upgrade to WPA2 or WPA3 encryption'
            })
        
        # Check for WPA2 with TKIP
        elif encryption == 'WPA2' and 'TKIP' in network.get('cipher', ''):
            vulnerabilities.append({
                'type': 'WEAK_CIPHER',
                'description': 'WPA2 with TKIP cipher is less secure than CCMP/AES',
                'recommendation': 'Configure router to use WPA2 with AES/CCMP only'
            })
        
        return vulnerabilities

if __name__ == '__main__':
    # Test the scanner when run directly
    scanner = WiFiScanner(verbose=True)
    networks = scanner.scan()
    
    print('\nScanned Networks:')
    for network in networks:
        print(f"\nSSID: {network['ssid']}")
        print(f"Encryption: {network.get('encryption', 'Unknown')}")
        print(f"Signal Strength: {network.get('signal', 'Unknown')}%")
        print(f"Security Risk: {network.get('security_risk', 'Unknown')}")
        
        print("Vulnerabilities:")
        if network['vulnerabilities']:
            for vuln in network['vulnerabilities']:
                print(f"  - {vuln['type']}: {vuln['description']}")
                print(f"    Recommendation: {vuln['recommendation']}")
        else:
            print("  No vulnerabilities detected")