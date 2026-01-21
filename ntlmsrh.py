#!/usr/bin/env python3
"""
NTLMSRH - NTLM Search & Reconnaissance Hunter
A modernized, enhanced NTLM endpoint discovery and analysis tool

Based on the original NTLMRecon by @pwnfoo and @nyxgeek
Enhanced and modernized by Philip Burnham @lokii-git

Original NTLMRecon: https://github.com/pwnfoo/ntlmrecon
Original NTLMScan concept: @nyxgeek
"""

import argparse
import json
import os
import sys
import signal
import requests
import ipaddress
import random
import time
import base64
import struct
import socket
from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import init, Fore, Back, Style

# Initialize colorama for cross-platform colored terminal text
init(autoreset=True)

# Professional Color Scheme - Consistent & Readable
class Colors:
    # Primary colors for different message types
    SUCCESS = Fore.GREEN     # [+] Success messages, found endpoints
    ERROR = Fore.RED         # [!] Errors, failures, warnings  
    INFO = Fore.CYAN         # [*] Information, progress updates
    HEADER = Fore.YELLOW     # Headers, banners, important info
    DATA = Fore.WHITE        # Data values, neutral information
    HIGHLIGHT = Fore.MAGENTA # Special highlights, counts, summaries
    RESET = Style.RESET_ALL  # Reset to default

# Disable SSL warnings for pentesting
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# =============================================================================
# CONFIGURATION
# =============================================================================
VERSION = "1.0.0"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
DEFAULT_TIMEOUT = 10
MAX_THREADS = 20
# Comprehensive NTLM paths from original NTLMRecon + additional discoveries
DEFAULT_PATHS = [
    '/abs',
    '/adfs/services/trust/2005/windowstransport',
    '/adfs/ls/wia',
    '/api/',
    '/aspnet_client/',
    '/Autodiscover',
    '/Autodiscover/AutodiscoverService.svc/root',
    '/Autodiscover/Autodiscover.xml',
    '/AutoUpdate/',
    '/CertEnroll/',
    '/CertProv',
    '/CertSrv/',
    '/Conf/',
    '/debug/',
    '/deviceupdatefiles_ext/',
    '/deviceupdatefiles_int/',
    '/dialin',
    '/ecp/',
    '/Etc/',
    '/EWS/',
    '/Exchange/',
    '/Exchweb/',
    '/GroupExpansion/',
    '/HybridConfig',
    '/iwa/authenticated.aspx',
    '/iwa/iwa_test.aspx',
    '/mcx',
    '/meet',
    '/Microsoft-Server-ActiveSync/',
    '/OAB/',
    '/ocsp/',
    '/owa/',
    '/PersistentChat',
    '/PhoneConferencing/',
    '/PowerShell/',
    '/Public/',
    '/Reach/sip.svc',
    '/reports/',
    '/RequestHandler/',
    '/RequestHandlerExt',
    '/RequestHandlerExt/',
    '/Rgs/',
    '/RgsClients',
    '/Rpc/',
    '/RpcWithCert/',
    '/scheduler',
    '/sso',
    '/Ucwa',
    '/UnifiedMessaging/',
    '/WebTicket',
    '/WebTicket/WebTicketService.svc',
    '/_windows/default.aspx?ReturnUrl=/',
    # Additional common paths
    '/mapi/',
    '/rpc/rpcproxy.dll',
    '/Rpc/RpcProxy.dll',
    '/rpcwithcert/rpcproxy.dll',
    '/certsrv/',
    '/EWS/Exchange.asmx',
    '/autodiscover/',
    '/autodiscover/autodiscover.xml',
    '/ews/exchange.asmx',
    '/ews/',
    '/exchange/',
    '/adfs/',
    '/portal/',
    '/remote/',
    '/citrix/',
    '/vpn/',
    '/webmail/',
    '/mail/',
    '/email/',
    '/connect/',
    '/login/',
    '/auth/',
    '/authentication/',
    '/secure/',
    '/private/'
]

class NTLMSRHScanner:
    def __init__(self, threads=15, timeout=1, verbose=False):  # Hardcoded aggressive timeout for speed
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.results = []
        self.lock = threading.Lock()
        
        # Setup requests session with faster retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=2,  # Reduced retries for speed
            backoff_factor=0.5,  # Faster backoff
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
    def quick_host_check(self, target_url):
        """Quick connectivity check before full NTLM scan"""
        try:
            # Extract hostname from URL
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            hostname = parsed.hostname or parsed.netloc
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            # Quick TCP connect test (faster than full HTTP request)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # 1 second timeout for connectivity check
            result = sock.connect_ex((hostname, port))
            sock.close()
            
            return result == 0  # 0 means connection successful
            
        except (socket.gaierror, socket.timeout, Exception):
            return False  # Host unreachable or invalid
    
    def load_targets(self, target_input):
        """Load targets from file, IP, CIDR range, or URL"""
        targets = []
        
        # Check if it's a file (use current working directory for relative paths)
        target_path = os.path.abspath(target_input) if not os.path.isabs(target_input) else target_input
        
        if os.path.isfile(target_path):
            try:
                with open(target_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            targets.extend(self._parse_target(line))
                print(f"{Colors.SUCCESS}[+] Loaded {len(set(targets))} targets from file: {target_input}{Colors.RESET}")
            except (IOError, OSError) as e:
                print(f"{Colors.ERROR}[!] Error reading target file '{target_input}': {e}{Colors.RESET}")
                sys.exit(1)
        else:
            # Single target
            targets.extend(self._parse_target(target_input))
            
        return list(set(targets))  # Remove duplicates
    
    def _parse_target(self, target):
        """Parse individual target (URL, IP, CIDR, or hostname)"""
        targets = []
        
        # If it's already a URL, use it directly
        if target.startswith(('http://', 'https://')):
            targets.append(target)
            return targets
            
        try:
            # Try as CIDR range
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())
                
                # Scan ALL IPs in the CIDR range
                print(f"{Colors.INFO}[*] CIDR range {target} contains {len(hosts)} hosts - scanning all{Colors.RESET}")
                for ip in hosts:
                    targets.append(f"https://{ip}")  # Only HTTPS for NTLM
            else:
                # Single IP or hostname
                try:
                    ipaddress.ip_address(target)  # Validate IP
                    targets.append(f"https://{target}")  # Only HTTPS for NTLM
                except ValueError:
                    # Hostname
                    targets.append(f"https://{target}")  # Only HTTPS for NTLM
                    
        except ValueError:
            print(f"Invalid target format: {target}")
            
        return targets
    
    def generate_ntlm_negotiate(self):
        """Generate NTLM Type 1 (Negotiate) message"""
        # NTLM Type 1 Message (simplified for better compatibility)
        signature = b'NTLMSSP\x00'  # NTLM signature  
        message_type = struct.pack('<L', 1)  # Type 1 message
        flags = struct.pack('<L', 0x88202)  # Standard negotiate flags
        # Empty domain and workstation fields for maximum compatibility
        empty_fields = b'\x00' * 16  # 8 bytes each for domain and workstation descriptors
        
        msg = signature + message_type + flags + empty_fields
        return base64.b64encode(msg).decode('ascii')
    
    def parse_ntlm_response(self, ntlm_data):
        """Parse NTLM Type 2 (Challenge) response to extract domain info"""
        try:
            ntlm_bytes = base64.b64decode(ntlm_data)
            
            # Verify NTLMSSP signature
            if ntlm_bytes[:8] != b'NTLMSSP\x00':
                return None
                
            # Check message type (should be 2 for challenge)
            msg_type = struct.unpack('<L', ntlm_bytes[8:12])[0]
            if msg_type != 2:
                return None
                
            # Parse target name (domain)
            target_name_len = struct.unpack('<H', ntlm_bytes[12:14])[0]
            target_name_offset = struct.unpack('<L', ntlm_bytes[16:20])[0]
            
            # Parse flags
            flags = struct.unpack('<L', ntlm_bytes[20:24])[0]
            
            # Extract target information block offset
            target_info_len = struct.unpack('<H', ntlm_bytes[40:42])[0] 
            target_info_offset = struct.unpack('<L', ntlm_bytes[44:48])[0]
            
            result = {}
            
            # Extract domain name (try NetBIOS domain from target info first, fallback to target name)
            if target_name_len > 0 and target_name_offset < len(ntlm_bytes):
                try:
                    domain_name = ntlm_bytes[target_name_offset:target_name_offset + target_name_len]
                    # Try UTF-16LE first, then UTF-8 fallback
                    try:
                        result['domain'] = domain_name.decode('utf-16le').rstrip('\x00')
                    except UnicodeDecodeError:
                        result['domain'] = domain_name.decode('utf-8', errors='ignore').rstrip('\x00')
                except Exception:
                    pass
            
            # Parse target information block
            if target_info_len > 0 and target_info_offset < len(ntlm_bytes):
                target_info = ntlm_bytes[target_info_offset:target_info_offset + target_info_len]
                result.update(self._parse_target_info(target_info))
                
            return result
            
        except Exception as e:
            if self.verbose:
                print(f"Error parsing NTLM response: {e}")
            return None
    
    def _parse_target_info(self, target_info):
        """Parse NTLM target information block"""
        info = {}
        offset = 0
        
        while offset < len(target_info):
            if offset + 4 > len(target_info):
                break
                
            attr_type = struct.unpack('<H', target_info[offset:offset+2])[0]
            attr_len = struct.unpack('<H', target_info[offset+2:offset+4])[0]
            
            if attr_type == 0:  # End of list
                break
                
            if offset + 4 + attr_len > len(target_info):
                break
                
            attr_data = target_info[offset+4:offset+4+attr_len]
            
            try:
                decoded_data = attr_data.decode('utf-16le').rstrip('\x00')
                
                if attr_type == 1:  # NetBIOS computer name
                    info['server_name'] = decoded_data
                elif attr_type == 2:  # NetBIOS domain name
                    info['nb_domain_name'] = decoded_data
                elif attr_type == 3:  # DNS computer name
                    info['fqdn'] = decoded_data
                elif attr_type == 4:  # DNS domain name
                    info['dns_domain_name'] = decoded_data
                elif attr_type == 5:  # DNS tree name
                    info['parent_dns_domain'] = decoded_data
                    
            except UnicodeDecodeError:
                pass
                
            offset += 4 + attr_len
            
        return info
    
    def test_ntlm_endpoint(self, url, path='/'):
        """Test a single URL for NTLM authentication"""
        test_url = urljoin(url, path)
        
        try:
            # Generate NTLM negotiate message
            ntlm_negotiate = self.generate_ntlm_negotiate()
            
            headers = {
                'Authorization': f'NTLM {ntlm_negotiate}',
                'User-Agent': USER_AGENT,
                'Accept': '*/*',
                'Connection': 'close'
            }
            
            response = self.session.get(
                test_url, 
                headers=headers, 
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            
            # Look for NTLM challenge in response
            www_auth = response.headers.get('WWW-Authenticate', '')
            if 'NTLM' in www_auth and len(www_auth.split()) > 1:
                ntlm_response = www_auth.split()[1]
                
                # Parse the NTLM response
                ntlm_info = self.parse_ntlm_response(ntlm_response)
                
                if ntlm_info:
                    result = {
                        'url': test_url,
                        'status_code': response.status_code,
                        'server_header': response.headers.get('Server', 'Unknown'),
                        'timestamp': datetime.now().isoformat(),
                        **ntlm_info
                    }
                    
                    with self.lock:
                        self.results.append(result)
                    
                    return result
                    
        except requests.exceptions.Timeout:
            if self.verbose:
                print(f"Timeout: {test_url}")
        except requests.exceptions.ConnectionError:
            if self.verbose:
                print(f"Connection error: {test_url}")
        except Exception as e:
            if self.verbose:
                print(f"Error testing {test_url}: {e}")
                
        return None
    
    def scan_target(self, base_url):
        """Scan a target URL against all default paths"""
        # Extract clean host from URL for display  
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        clean_host = parsed.hostname or parsed.netloc
        
        # Quick connectivity check before full scan
        if not self.quick_host_check(base_url):
            return []  # Return empty results for unreachable hosts
        
        results = []
        
        for path in DEFAULT_PATHS:
            result = self.test_ntlm_endpoint(base_url, path)
            if result:
                results.append(result)
                if self.verbose:
                    print(f"   {Colors.SUCCESS}[+] Found NTLM: {result['url']}{Colors.RESET}")
                    
        return results
    
    def display_result(self, result, count):
        """Display a single NTLM result in enhanced format"""
        print(f"\n{Colors.HEADER}[NTLM] Endpoint #{count}: {result['url']}{Colors.RESET}")
        print(f"   {Colors.DATA}Status Code      : {result.get('status_code', 'N/A')}{Colors.RESET}")
        print(f"   {Colors.DATA}Server          : {result.get('server_header', 'N/A')}{Colors.RESET}")
        
        if result.get('nb_domain_name') or result.get('domain'):
            # Prefer NetBIOS domain name if available, fallback to domain
            domain_name = result.get('nb_domain_name') or result.get('domain')
            print(f"   {Colors.SUCCESS}AD Domain Name   : {domain_name}{Colors.RESET}")
        if result.get('server_name'):
            print(f"   {Colors.SUCCESS}Server Name      : {result['server_name']}{Colors.RESET}")
        if result.get('dns_domain_name'):
            print(f"   {Colors.SUCCESS}DNS Domain Name  : {result['dns_domain_name']}{Colors.RESET}")
        if result.get('fqdn'):
            print(f"   {Colors.SUCCESS}FQDN            : {result['fqdn']}{Colors.RESET}")
        if result.get('parent_dns_domain'):
            print(f"   {Colors.SUCCESS}Parent DNS      : {result['parent_dns_domain']}{Colors.RESET}")
            
        print("="*70)
    
    def scan_multiple_targets(self, targets):
        """Scan multiple targets with threading"""
        completed_count = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_target = {executor.submit(self.scan_target, target): target for target in targets}
            
            for future in as_completed(future_to_target):
                # Check for shutdown signal
                if shutdown_requested:
                    print(f"{Colors.ERROR}[!] Cancelling remaining scans...{Colors.RESET}")
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                    
                target = future_to_target[future]
                completed_count += 1
                
                # Extract clean host for display
                from urllib.parse import urlparse
                parsed = urlparse(target)
                clean_host = parsed.hostname or parsed.netloc
                
                try:
                    results = future.result()
                    if results:
                        print(f"{Colors.SUCCESS}[+] {clean_host} ({completed_count}/{len(targets)}): {len(results)} NTLM endpoints found{Colors.RESET}")
                    else:
                        # Check if host was reachable by trying quick connectivity test
                        if not self.quick_host_check(target):
                            print(f"{Colors.ERROR}[-] {clean_host} ({completed_count}/{len(targets)}): Host unreachable/filtered{Colors.RESET}")
                        else:
                            print(f"{Colors.ERROR}[-] {clean_host} ({completed_count}/{len(targets)}): No NTLM endpoints{Colors.RESET}")
                        
                except Exception as e:
                    print(f"{Colors.ERROR}[!] {clean_host} ({completed_count}/{len(targets)}): Error - {e}{Colors.RESET}")
    
    def save_report(self, filename="ntlmsrh_report.json"):
        """Save comprehensive JSON report"""
        report = {
            'tool': 'ntlmsrh',
            'version': VERSION,
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_endpoints': len(self.results),
                'unique_domains': len(set(r.get('domain', '') for r in self.results if r.get('domain'))),
                'unique_servers': len(set(r.get('server_name', '') for r in self.results if r.get('server_name')))
            },
            'results': self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
            
        print(f"\n{Colors.SUCCESS}[+] JSON report saved to: {filename}{Colors.RESET}")

    def save_text_report(self, filename="ntlmsrh_report.txt"):
        """Save formatted text report similar to display_ntlmrecon.py"""
        if not self.results:
            return
            
        with open(filename, 'w') as f:
            f.write("="*70 + "\n")
            f.write(" NTLM Authentication Endpoints Discovered \n")
            f.write("="*70 + "\n")
            
            for i, result in enumerate(self.results, 1):
                f.write(f"\n[NTLM] Endpoint #{i}: {result['url']}\n")
                f.write(f"   Status Code      : {result.get('status_code', 'N/A')}\n")
                f.write(f"   Server          : {result.get('server_header', 'N/A')}\n")
                f.write(f"   AD Domain Name   : {result.get('domain', 'N/A')}\n")
                f.write(f"   Server Name      : {result.get('server_name', 'N/A')}\n")
                f.write(f"   DNS Domain Name  : {result.get('dns_domain_name', 'N/A')}\n")
                f.write(f"   FQDN            : {result.get('fqdn', 'N/A')}\n")
                f.write(f"   Parent DNS      : {result.get('parent_dns_domain', 'N/A')}\n")
                f.write("="*70 + "\n")
        
        print(f"\n{Colors.SUCCESS}[+] Formatted text report saved to: {filename}{Colors.RESET}")

    def save_endpoints_list(self, filename="endpoints.txt"):
        """Save simple list of discovered NTLM endpoints for PlexTrac/reporting"""
        if not self.results:
            return
            
        with open(filename, 'w') as f:
            f.write("# NTLM Authentication Endpoints Discovered\n")
            f.write("# Format: URL (IP)\n")
            f.write("# Ready for PlexTrac 'Affected Assets' copy-paste\n\n")
            
            for result in self.results:
                url = result['url']
                try:
                    # Extract IP from URL for reference
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    hostname = parsed.hostname
                    
                    # Try to resolve to IP if it's a hostname
                    try:
                        import socket
                        if not hostname.replace('.', '').isdigit():  # Not already an IP
                            ip = socket.gethostbyname(hostname)
                            f.write(f"{url} ({ip})\n")
                        else:
                            f.write(f"{url}\n")
                    except (socket.gaierror, AttributeError):
                        # If resolution fails, just write the URL
                        f.write(f"{url}\n")
                        
                except Exception:
                    # Fallback - just write the URL
                    f.write(f"{url}\n")
        
        print(f"{Colors.SUCCESS}[+] Endpoints list saved to: {filename}{Colors.RESET}")

# Global flag for graceful shutdown
shutdown_requested = False

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    global shutdown_requested
    shutdown_requested = True
    print(f"\n\n{Colors.ERROR}[!] Interrupt received (Ctrl+C). Gracefully shutting down...{Colors.RESET}")
    print(f"{Colors.INFO}[*] Saving partial results and exiting cleanly...{Colors.RESET}")
    sys.exit(0)

def main():
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    # ASCII Art Banner
    print(f"{Colors.INFO}" + r"""
 _   _ _____ _     ___  ___ ___________ _   _ 
| \ | |_   _| |    |  \/  |/  ___| ___ \ | | |
|  \| | | | | |    | .  . |\ `--.| |_/ / |_| |
| . ` | | | | |    | |\/| | `--. \    /|  _  |
| |\  | | | | |____| |  | |/\__/ / |\ \| | | |
\_| \_/ \_/ \_____/\_|  |_/\____/\_| \_\_| |_/
                                              
""" + Colors.RESET)
    print(f"{Colors.HEADER}NTLM Search & Reconnaissance Hunter v{VERSION}{Colors.RESET}")
    print(f"{Colors.DATA}Based on NTLMRecon by @pwnfoo & @nyxgeek{Colors.RESET}")
    print(f"{Colors.DATA}Enhanced by @lokii-git{Colors.RESET}")
    print(f"{Colors.HIGHLIGHT}Loaded {len(DEFAULT_PATHS)} paths for NTLM endpoint testing{Colors.RESET}\n")
    
    parser = argparse.ArgumentParser(description="NTLMSRH - NTLM Search & Reconnaissance Hunter")
    parser.add_argument('target', help='Target IP, URL, CIDR range, or file containing targets')
    parser.add_argument('-t', '--threads', type=int, default=15, help='Number of threads (default: 15)')
    parser.add_argument('-o', '--output', help='Save formatted text output to file (optional)')
    parser.add_argument('-j', '--json', help='Save JSON report to specified file (optional)')
    parser.add_argument('--timeout', type=int, default=1, help='Request timeout in seconds (default: 1)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--paths', help='Custom paths file (one per line)')
    args = parser.parse_args()
    
    # Load custom paths if provided
    if args.paths:
        paths_file = os.path.abspath(args.paths) if not os.path.isabs(args.paths) else args.paths
        if os.path.isfile(paths_file):
            try:
                with open(paths_file, 'r') as f:
                    custom_paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                DEFAULT_PATHS.extend(custom_paths)
                print(f"{Colors.SUCCESS}[+] Loaded {len(custom_paths)} custom paths from: {args.paths}{Colors.RESET}")
            except (IOError, OSError) as e:
                print(f"{Colors.ERROR}[!] Error reading paths file '{args.paths}': {e}{Colors.RESET}")
                sys.exit(1)
        else:
            print(f"{Colors.ERROR}[!] Custom paths file not found: {args.paths}{Colors.RESET}")
            sys.exit(1)
    
    # Initialize scanner
    scanner = NTLMSRHScanner(threads=args.threads, timeout=args.timeout, verbose=args.verbose)
    
    # Load targets
    print(f"{Colors.INFO}[*] Loading targets from: {args.target}{Colors.RESET}")
    targets = scanner.load_targets(args.target)
    
    if not targets:
        print(f"{Colors.ERROR}[!] No valid targets found{Colors.RESET}")
        sys.exit(1)
        
    print(f"{Colors.SUCCESS}[+] Found {len(targets)} targets to scan{Colors.RESET}")
    print(f"{Colors.INFO}[*] Testing {len(DEFAULT_PATHS)} paths per target{Colors.RESET}")
    
    # Perform scans
    if len(targets) == 1:
        # Single target - detailed output
        results = scanner.scan_target(targets[0])
        if results:
            print(f"\n{'='*70}")
            print(" NTLM Authentication Endpoints Discovered ")
            print(f"{'='*70}")
            
            for i, result in enumerate(results, 1):
                scanner.display_result(result, i)
        else:
            print(f"\n{Colors.ERROR}[-] No NTLM endpoints found on {targets[0]}{Colors.RESET}")
    else:
        # Multiple targets - threaded scanning
        scanner.scan_multiple_targets(targets)
        
        # Display summary
        if scanner.results:
            print(f"\n{'='*70}")
            print(" NTLM Authentication Endpoints Discovered ")
            print(f"{'='*70}")
            
            for i, result in enumerate(scanner.results, 1):
                scanner.display_result(result, i)
    
    # Save reports if requested and always save endpoints list
    if scanner.results:
        # Always save simple endpoints list for easy reporting (in current directory)
        endpoints_file = os.path.abspath("endpoints.txt")
        scanner.save_endpoints_list(endpoints_file)
        
        if args.output:
            output_file = os.path.abspath(args.output) if not os.path.isabs(args.output) else args.output
            scanner.save_text_report(output_file)
        if args.json:
            json_file = os.path.abspath(args.json) if not os.path.isabs(args.json) else args.json
            scanner.save_report(json_file)
    
    # Display final summary if results found
    if scanner.results:
        unique_domains = len(set(r.get('domain', '') for r in scanner.results if r.get('domain')))
        unique_servers = len(set(r.get('server_name', '') for r in scanner.results if r.get('server_name')))
        
        print(f"\n{Colors.HIGHLIGHT}[SUMMARY] Scan Results:{Colors.RESET}")
        print(f"   Total Targets: {len(targets)}")
        print(f"   NTLM Endpoints: {len(scanner.results)}")
        print(f"   Unique Domains: {unique_domains}")
        print(f"   Unique Servers: {unique_servers}")
    else:
        print(f"\n{Colors.ERROR}[-] No NTLM endpoints discovered across {len(targets)} targets{Colors.RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.ERROR}[!] Scan interrupted by user (Ctrl+C){Colors.RESET}")
        print(f"{Colors.INFO}[*] Exiting gracefully...{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.ERROR}[!] Unexpected error: {e}{Colors.RESET}")
        print(f"{Colors.INFO}[*] Please report this issue if it persists{Colors.RESET}")
        sys.exit(1)