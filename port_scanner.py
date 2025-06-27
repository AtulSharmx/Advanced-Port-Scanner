#!/usr/bin/env python3

"""
Advanced Network Scanner v3.0
- TCP Connect & SYN Stealth Scanning
- Service Fingerprinting
- Basic Vulnerability Checks
- Comprehensive Reporting
- CIDR Range Support
"""

import socket
import sys
import json
import ipaddress
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from collections import defaultdict
import scapy.all as scapy
from packaging import version

# Constants
DEFAULT_PORTS = "1-1024"
MAX_THREADS = 200
TIMEOUT = 1.0
REPORT_TEMPLATE = """
# Network Scan Report

**Scan Date:** {date}
**Target:** {target}
**Scan Type:** {scan_type}

## Summary
- **Hosts Scanned:** {hosts_scanned}
- **Open Ports Found:** {open_ports}
- **Vulnerabilities Detected:** {vulns_found}

## Detailed Results
{results}

## Recommendations
{recommendations}
"""

# Service Vulnerabilities Database
VULN_DB = {
    'ftp': {
        'anonymous': {'severity': 'medium', 'description': 'Anonymous FTP login allowed'},
        'vsftpd-2.3.4': {'severity': 'critical', 'description': 'VSFTPD 2.3.4 backdoor vulnerability'}
    },
    'ssh': {
        'OpenSSH-7.4': {'severity': 'high', 'description': 'Outdated OpenSSH version with known vulnerabilities'}
    },
    'http': {
        'Apache-2.4.29': {'severity': 'medium', 'description': 'Apache server with potential vulnerabilities'}
    }
}

class Scanner:
    def __init__(self):
        self.results = defaultdict(list)
        self.vulnerabilities = []
        self.hosts_scanned = 0

    def parse_ports(self, port_input):
        """Parse port ranges like '80,443,8000-9000'"""
        ports = set()
        for part in port_input.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        return sorted(ports)

    def tcp_scan(self, ip, port):
        """Standard TCP Connect Scan"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def syn_scan(self, ip, port):
        """Stealth SYN Scan (requires root)"""
        try:
            pkt = scapy.IP(dst=ip)/scapy.TCP(dport=port, flags="S")
            resp = scapy.sr1(pkt, timeout=TIMEOUT, verbose=0)
            if resp and resp.haslayer(scapy.TCP):
                if resp.getlayer(scapy.TCP).flags == 0x12:  # SYN-ACK
                    scapy.send(scapy.IP(dst=ip)/scapy.TCP(dport=port, flags="R"), verbose=0)
                    return True
            return False
        except:
            return False

    def service_fingerprint(self, ip, port):
        """Identify service and version"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((ip, port))
            
            # HTTP Service
            if port == 80 or port == 443:
                sock.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                banner = sock.recv(1024).decode(errors='ignore').lower()
                if 'apache' in banner:
                    return 'http', self.parse_apache_version(banner)
                elif 'nginx' in banner:
                    return 'http', 'nginx'
            
            # SSH Service
            elif port == 22:
                banner = sock.recv(1024).decode(errors='ignore')
                if 'openssh' in banner.lower():
                    return 'ssh', self.parse_ssh_version(banner)
            
            # Generic fallback
            service = socket.getservbyport(port, 'tcp') if port <= 1024 else 'unknown'
            return service, None
            
        except:
            return 'unknown', None
        finally:
            sock.close()

    def check_vulnerabilities(self, service, version):
        """Check for known vulnerabilities"""
        vulns = []
        if service in VULN_DB:
            if version and version in VULN_DB[service]:
                vulns.append(VULN_DB[service][version])
            if 'anonymous' in VULN_DB[service] and service == 'ftp':
                vulns.append(VULN_DB[service]['anonymous'])
        return vulns

    def scan_host(self, ip, ports, scan_type='tcp'):
        """Scan a single host"""
        self.hosts_scanned += 1
        print(f"\n[*] Scanning {ip}...")
        
        for port in ports:
            is_open = False
            if scan_type == 'syn' and scapy.conf.root:
                is_open = self.syn_scan(ip, port)
            else:
                is_open = self.tcp_scan(ip, port)
            
            if is_open:
                service, ver = self.service_fingerprint(ip, port)
                vulns = self.check_vulnerabilities(service, ver)
                
                result = {
                    'port': port,
                    'service': service,
                    'version': ver,
                    'status': 'open'
                }
                
                if vulns:
                    result['vulnerabilities'] = vulns
                    self.vulnerabilities.extend(vulns)
                    print(f"[!] {ip}:{port} - {service} {ver} - VULNERABLE")
                else:
                    print(f"[+] {ip}:{port} - {service} {ver}")
                
                self.results[ip].append(result)
    
    def generate_report(self, target, scan_type, output_file):
        """Generate comprehensive report"""
        report_data = {
            'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'target': target,
            'scan_type': scan_type,
            'hosts_scanned': self.hosts_scanned,
            'open_ports': sum(len(v) for v in self.results.values()),
            'vulns_found': len(self.vulnerabilities),
            'results': json.dumps(self.results, indent=2),
            'recommendations': self.generate_recommendations()
        }
        
        with open(output_file, 'w') as f:
            f.write(REPORT_TEMPLATE.format(**report_data))
        
        print(f"\n[+] Report saved to {output_file}")

    def generate_recommendations(self):
        """Generate security recommendations"""
        recs = []
        if self.vulnerabilities:
            recs.append("- Update vulnerable services to latest versions")
            recs.append("- Disable anonymous FTP if enabled")
            recs.append("- Implement firewall rules to restrict unnecessary ports")
        else:
            recs.append("- No critical vulnerabilities found. Maintain current security posture.")
        return "\n".join(recs)

def main():
    parser = argparse.ArgumentParser(
        description="Professional Network Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("target", help="IP, hostname, or CIDR range")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="Ports to scan")
    parser.add_argument("-t", "--threads", type=int, default=MAX_THREADS, help="Max threads")
    parser.add_argument("-s", "--scan-type", choices=['tcp', 'syn'], default='tcp', help="Scan type")
    parser.add_argument("-o", "--output", default="scan_report.md", help="Output file")
    args = parser.parse_args()

    scanner = Scanner()
    ports = scanner.parse_ports(args.ports)
    
    try:
        # Handle IP ranges
        if '/' in args.target:
            network = ipaddress.ip_network(args.target, strict=False)
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                for ip in network.hosts():
                    executor.submit(scanner.scan_host, str(ip), ports, args.scan_type)
        else:
            scanner.scan_host(args.target, ports, args.scan_type)
        
        scanner.generate_report(args.target, args.scan_type, args.output)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("""
    ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
    ██╔══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██████╔╝██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║
    ██╔═══╝ ██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║
    ██║     ██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║
    ╚═╝     ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    """)
    main()