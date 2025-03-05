#!/usr/bin/env python3
# Main entry point for Wi-Fi Security Assessment Tool
# Authors: Jack Merritt and Thomas Busick

import sys
import os
import argparse
import datetime

# Add the parent directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.scanner import WiFiScanner

def generate_report(networks, output_file, format='txt'):
    """Generate a report for the analyzed networks"""
    
    # Create the output directory if it doesn't exist
    output_dir = os.path.dirname(output_file)
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
                f.write(f'  Signal Strength: {network.get("signal", "Unknown")}%\n')
                f.write(f'  Security Risk: {network.get("security_risk", "Unknown")}\n')
                
                f.write('\n  Vulnerabilities:\n')
                if network.get('vulnerabilities'):
                    for vuln in network['vulnerabilities']:
                        f.write(f'    - {vuln.get("type", "Unknown")}: {vuln.get("description", "")}\n')
                        f.write(f'      Recommendation: {vuln.get("recommendation", "")}\n\n')
                else:
                    f.write('    No vulnerabilities detected\n\n')
                    
                f.write('\n')
            
            f.write('\nEnd of Report\n')
    else:
        print(f'Report format {format} not yet implemented.')

def display_networks(networks):
    """Display networks in a readable format"""
    
    if not networks:
        print('No networks found.')
        return
    
    # Group networks by security risk
    networks_by_risk = {'HIGH': [], 'MEDIUM': [], 'LOW': [], 'VERY LOW': [], 'UNKNOWN': []}
    
    for network in networks:
        risk = network.get('security_risk', 'UNKNOWN')
        networks_by_risk[risk].append(network)
    
    # Display networks by risk level
    risk_order = ['HIGH', 'MEDIUM', 'LOW', 'VERY LOW', 'UNKNOWN']
    
    print('\nNetworks by Security Risk:')
    print('=========================')
    
    for risk in risk_order:
        risk_networks = networks_by_risk[risk]
        if risk_networks:
            print(f'\n{risk} Risk Networks ({len(risk_networks)}):')
            for network in risk_networks:
                ssid = network.get('ssid', 'Unknown')
                encryption = network.get('encryption', 'Unknown')
                signal = network.get('signal', 'Unknown')
                
                print(f'  • {ssid} - {encryption} (Signal: {signal}%)')
    
    print('\nDetailed Network Information:')
    print('============================')
    
    for i, network in enumerate(networks):
        print(f"\n{i+1}. SSID: {network.get('ssid', 'Unknown')}")
        print(f"   Encryption: {network.get('encryption', 'Unknown')}")
        print(f"   Authentication: {network.get('authentication', 'Unknown')}")
        print(f"   Signal Strength: {network.get('signal', 'Unknown')}%")
        print(f"   Security Risk: {network.get('security_risk', 'Unknown')}")
        
        print("   Vulnerabilities:")
        if network.get('vulnerabilities'):
            for vuln in network['vulnerabilities']:
                print(f"     - {vuln.get('type', 'Unknown')}: {vuln.get('description', '')}")
                print(f"       Recommendation: {vuln.get('recommendation', '')}")
        else:
            print("     No vulnerabilities detected")

def main():
    """Main entry point for the application"""
    
    # Create argument parser
    parser = argparse.ArgumentParser(
        description='Wi-Fi Security Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Example: python main.py -s -o reports/wifi_report.txt'
    )
    
    parser.add_argument('-s', '--scan', action='store_true', help='Scan for nearby networks')
    parser.add_argument('-o', '--output', type=str, help='Output report file')
    parser.add_argument('-f', '--format', type=str, choices=['txt', 'html', 'json', 'pdf'], 
                        default='txt', help='Report format')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Display header
    print('=' * 60)
    print('Wi-Fi Security Assessment Tool')
    print('Created by Jack Merritt and Thomas Busick')
    print('=' * 60)
    
    # Default behavior if no arguments provided
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    # Scan for networks if requested
    if args.scan:
        print('Scanning for nearby Wi-Fi networks...')
        scanner = WiFiScanner(verbose=args.verbose)
        networks = scanner.scan()
        print(f'Found {len(networks)} networks')
        
        # Display networks
        display_networks(networks)
        
        # Generate a report if output file specified
        if args.output:
            print(f'\nGenerating {args.format.upper()} report...')
            generate_report(networks, args.output, args.format)
            print(f'Report saved to {args.output}')

if __name__ == '__main__':
    main()