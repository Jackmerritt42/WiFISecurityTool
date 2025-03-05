#!/usr/bin/env python3
# Main entry point for Wi-Fi Security Assessment Tool
# Authors: Jack Merritt and Thomas Busick

import sys
import os
import argparse
import datetime
import json
import platform
import time
import subprocess
from pathlib import Path

# Try to import colorama for cross-platform colored output
try:
    from colorama import init, Fore, Style
    colorama_available = True
    init()
except ImportError:
    colorama_available = False

# Import our scanner module - adjust path as needed
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

# Try importing the scanner module
try:
    from src.core.scanner import WiFiScanner
except ImportError:
    # If we're in src directory, try different path
    sys.path.append(os.path.dirname(current_dir))
    try:
        from core.scanner import WiFiScanner
    except ImportError:
        print("Error: Could not import the WiFiScanner module.")
        print("Make sure you're running this script from the correct directory.")
        sys.exit(1)

def colored_text(text, color_code, bold=False):
    """Add color to text if colorama is available"""
    if colorama_available:
        bold_code = Style.BRIGHT if bold else ""
        return f"{bold_code}{color_code}{text}{Style.RESET_ALL}"
    return text

def generate_report(networks, output_file, format='txt'):
    """Generate a report for the analyzed networks"""
    
    # Create the output directory if it doesn't exist
    output_dir = os.path.dirname(output_file) if output_file else ""
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    if format == 'txt':
        with open(output_file, 'w') as f:
            f.write('Wi-Fi Security Assessment Report\n')
            f.write('===============================\n\n')
            f.write(f'Date: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n\n')
            f.write(f'Networks Found: {len(networks)}\n\n')
            
            if not networks:
                f.write('No networks found.\n')
                return
            
            # Count networks by risk level
            risk_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'VERY LOW': 0, 'UNKNOWN': 0}
            for network in networks:
                risk = network.get('security_risk', 'UNKNOWN')
                risk_counts[risk] = risk_counts.get(risk, 0) + 1
            
            f.write('Summary:\n')
            for risk, count in risk_counts.items():
                if count > 0:
                    f.write(f'  {risk} Risk: {count} networks\n')
            f.write('\n')
            
            # Network details
            f.write('Network Details:\n')
            f.write('---------------\n\n')
            
            for i, network in enumerate(networks):
                f.write(f'Network {i+1}: {network.get("ssid", "Unknown")}\n')
                f.write(f'  Encryption: {network.get("encryption", "Unknown")}\n')
                if network.get('channel'):
                    f.write(f'  Channel: {network.get("channel")}\n')
                f.write(f'  Signal Strength: {network.get("signal", "Unknown")}%\n')
                f.write(f'  Security Risk: {network.get("security_risk", "Unknown")}\n')
                
                if network.get('bssids'):
                    f.write(f'  MAC Address: {network["bssids"][0]["bssid"]}\n')
                
                f.write('\n  Vulnerabilities:\n')
                if network.get('vulnerabilities'):
                    for vuln in network['vulnerabilities']:
                        f.write(f'    - {vuln.get("type", "Unknown")}: {vuln.get("description", "")}\n')
                        f.write(f'      Recommendation: {vuln.get("recommendation", "")}\n\n')
                else:
                    f.write('    No vulnerabilities detected\n\n')
                    
                f.write('\n')
            
            f.write('\nEnd of Report\n')
            
        print(f"Report saved to {output_file}")
    
    elif format == 'json':
        # Create a JSON report
        report_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'total_networks': len(networks),
            'networks': networks,
            'summary': {
                'risk_levels': {}
            }
        }
        
        # Add risk level summary
        risk_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'VERY LOW': 0, 'UNKNOWN': 0}
        for network in networks:
            risk = network.get('security_risk', 'UNKNOWN')
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        report_data['summary']['risk_levels'] = risk_counts
        
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2)
            
        print(f"JSON report saved to {output_file}")
        
    else:
        print(f"Unsupported report format: {format}")

def display_networks(networks):
    """Display networks in a readable format with color coding by risk level"""
    
    if not networks:
        print('No networks found.')
        return
    
    # Group networks by security risk
    networks_by_risk = {'HIGH': [], 'MEDIUM': [], 'LOW': [], 'VERY LOW': [], 'UNKNOWN': []}
    
    for network in networks:
        risk = network.get('security_risk', 'UNKNOWN')
        networks_by_risk[risk].append(network)
    
    # Color mapping for risk levels
    risk_colors = {
        'HIGH': Fore.RED if colorama_available else '',
        'MEDIUM': Fore.YELLOW if colorama_available else '',
        'LOW': Fore.GREEN if colorama_available else '',
        'VERY LOW': Fore.BLUE if colorama_available else '',
        'UNKNOWN': Fore.WHITE if colorama_available else ''
    }
    
    # Display networks by risk level
    risk_order = ['HIGH', 'MEDIUM', 'LOW', 'VERY LOW', 'UNKNOWN']
    
    print('\nNetworks by Security Risk:')
    print('=========================')
    
    for risk in risk_order:
        risk_networks = networks_by_risk[risk]
        if risk_networks:
            risk_text = colored_text(f'\n{risk} Risk Networks ({len(risk_networks)}):', risk_colors[risk], bold=True)
            print(risk_text)
            
            for network in risk_networks:
                ssid = network.get('ssid', 'Unknown')
                encryption = network.get('encryption', 'Unknown')
                signal = network.get('signal', 'Unknown')
                
                print(f"  • {ssid} - {encryption} (Signal: {signal}%)")
    
    print('\nDetailed Network Information:')
    print('============================')
    
    for i, network in enumerate(networks):
        risk = network.get('security_risk', 'UNKNOWN')
        ssid_text = colored_text(f"\n{i+1}. SSID: {network.get('ssid', 'Unknown')}", risk_colors[risk], bold=True)
        print(ssid_text)
        print(f"   Encryption: {network.get('encryption', 'Unknown')}")
        if network.get('channel'):
            print(f"   Channel: {network.get('channel')}")
        print(f"   Signal Strength: {network.get('signal', 'Unknown')}%")
        print(f"   Security Risk: {risk}")
        
        if network.get('bssids'):
            print(f"   MAC Address: {network['bssids'][0]['bssid']}")
        
        print("   Vulnerabilities:")
        if network.get('vulnerabilities'):
            for vuln in network['vulnerabilities']:
                vuln_type = vuln.get('type', 'Unknown')
                description = vuln.get('description', '')
                recommendation = vuln.get('recommendation', '')
                
                vuln_text = colored_text(f"     - {vuln_type}:", risk_colors[risk])
                print(f"{vuln_text} {description}")
                print(f"       Recommendation: {recommendation}")
        else:
            print("     No vulnerabilities detected")

def check_prerequisites():
    """Check if all required tools are installed"""
    required_tools = []
    
    if platform.system() == 'Linux':
        required_tools = ['iwlist', 'iw', 'ip']
        optional_tools = ['airmon-ng', 'airodump-ng']
        
        missing_tools = []
        for tool in required_tools:
            try:
                subprocess.check_output(['which', tool], stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError:
                missing_tools.append(tool)
        
        if missing_tools:
            print("Missing required tools: " + ", ".join(missing_tools))
            print("Please install these tools before continuing.")
            print("On Debian/Ubuntu/Raspberry Pi OS: sudo apt-get install wireless-tools iw iproute2")
            return False
        
        # Check for optional tools
        missing_optional = []
        for tool in optional_tools:
            try:
                subprocess.check_output(['which', tool], stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError:
                missing_optional.append(tool)
        
        if missing_optional:
            print("Note: Some optional tools are missing: " + ", ".join(missing_optional))
            print("These tools enable advanced features like monitor mode.")
            print("On Debian/Ubuntu/Raspberry Pi OS: sudo apt-get install aircrack-ng")
    
    return True

def main():
    """Main entry point for the application"""
    
    # Create argument parser
    parser = argparse.ArgumentParser(
        description='Wi-Fi Security Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Example: python main.py -s -i wlan0 -o reports/wifi_report.txt'
    )
    
    parser.add_argument('-s', '--scan', action='store_true', help='Scan for nearby networks')
    parser.add_argument('-i', '--interface', type=str, default='wlan0', help='Wireless interface to use (Linux only)')
    parser.add_argument('-o', '--output', type=str, help='Output report file')
    parser.add_argument('-f', '--format', type=str, choices=['txt', 'json'], 
                        default='txt', help='Report format')
    parser.add_argument('-m', '--monitor', action='store_true', help='Enable monitor mode (Linux only)')
    parser.add_argument('-c', '--continuous', type=int, metavar='SECONDS', 
                        help='Continuously scan every SECONDS')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Display header
    header = """
╭──────────────────────────────────────────────────────╮
│            Wi-Fi Security Assessment Tool            │
│              Created by Jack & Thomas                │
╰──────────────────────────────────────────────────────╯
"""
    print(header)
    
    # Default behavior if no arguments provided
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    # Check prerequisites
    if not check_prerequisites():
        return
    
    # Scan for networks if requested
    if args.scan:
        try:
            # Create scanner
            scanner = WiFiScanner(interface=args.interface, verbose=args.verbose)
            
            # Enable monitor mode if requested
            monitor_enabled = False
            if args.monitor and platform.system() == 'Linux':
                print("Enabling monitor mode...")
                monitor_enabled = scanner.enable_monitor_mode()
                if not monitor_enabled:
                    print("Failed to enable monitor mode. Running normal scan instead.")
            
            if args.continuous:
                try:
                    print(f"Starting continuous scan every {args.continuous} seconds. Press Ctrl+C to stop.")
                    scan_count = 0
                    
                    while True:
                        scan_count += 1
                        print(f"\nScan #{scan_count} at {datetime.datetime.now().strftime('%H:%M:%S')}")
                        print("Scanning for nearby Wi-Fi networks...")
                        
                        networks = scanner.scan()
                        print(f"Found {len(networks)} networks")
                        
                        # Display networks
                        display_networks(networks)
                        
                        # Generate a report if output file specified
                        if args.output:
                            # Add timestamp to filename for continuous mode
                            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                            filename, ext = os.path.splitext(args.output)
                            output_file = f"{filename}_{timestamp}{ext}"
                            
                            generate_report(networks, output_file, args.format)
                        
                        # Wait before next scan
                        time.sleep(args.continuous)
                
                except KeyboardInterrupt:
                    print("\nScan interrupted by user.")
            else:
                print("Scanning for nearby Wi-Fi networks...")
                networks = scanner.scan()
                print(f"Found {len(networks)} networks")
                
                # Display networks
                display_networks(networks)
                
                # Generate a report if output file specified
                if args.output:
                    generate_report(networks, args.output, args.format)
        
        except Exception as e:
            print(f"Error during scan: {str(e)}")
        
        finally:
            # Disable monitor mode if it was enabled
            if args.monitor and platform.system() == 'Linux' and 'scanner' in locals() and monitor_enabled:
                print("Disabling monitor mode...")
                scanner.disable_monitor_mode()

if __name__ == '__main__':
    main()