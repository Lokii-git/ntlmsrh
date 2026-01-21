# NTLMSRH v1.0 - NTLM Search & Reconnaissance Hunter

![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Version](https://img.shields.io/badge/version-1.0.0-brightgreen.svg)
![Status](https://img.shields.io/badge/status-production-success.svg)

**NTLMSRH** is a high-performance, modernized NTLM endpoint discovery and analysis tool designed for penetration testers and security professionals. Built as a complete evolution of NTLMRecon, NTLMSRH delivers faster scanning, better intelligence extraction, and professional reporting capabilities.

## 🎯 What Makes NTLMSRH Special

NTLMSRH isn't just an update - it's a complete reimagining of NTLM reconnaissance with modern pentesting workflows in mind:

### 🚀 **Performance & Efficiency**
- **Multi-threaded Architecture**: 15 concurrent threads by default for rapid enumeration
- **HTTPS-Only Scanning**: Focuses on realistic scenarios (NTLM is virtually never over HTTP)
- **Intelligent Retry Logic**: Handles network issues gracefully with backoff strategies
- **Session Connection Pooling**: Reuses connections for maximum speed

### 🎨 **Professional Output & UX**
- **Consistent Color Scheme**: Clean, readable terminal output perfect for screenshots
- **No Emoji Clutter**: Professional formatting suitable for client reports
- **Real-time Progress**: Clear feedback during scanning operations
- **Structured Results**: Organized endpoint discovery with detailed metadata

### 📊 **Advanced Intelligence Extraction**
- **Complete NTLM Parsing**: Extracts domain names, server names, DNS domains, FQDNs
- **Active Directory Context**: Provides full AD environment intelligence
- **NetBIOS & DNS Resolution**: Maps internal network structure
- **Server Fingerprinting**: Identifies Exchange, SharePoint, and other services

### 📋 **Enterprise-Ready Reporting**
- **PlexTrac Integration**: Auto-generated `endpoints.txt` for direct asset import
- **Multiple Output Formats**: Console, formatted text, and JSON reports
- **Automation-Friendly**: Structured data perfect for tool chaining
- **Client-Ready**: Professional reports suitable for deliverables

## 🔧 Key Enhancements from NTLMRecon

| Feature | NTLMRecon | NTLMSRH v1.0 |
|---------|-----------|--------------|
| **Threading** | Single-threaded | Multi-threaded (15 workers) |
| **Protocol Support** | HTTP + HTTPS | HTTPS-focused (realistic) |
| **CIDR Scanning** | Limited (50 IPs max) | Complete range scanning |
| **Output Formats** | Basic text | Text + JSON + PlexTrac |
| **Error Handling** | Basic | Comprehensive with retry logic |
| **Installation** | Manual setup | One-command installer |
| **Active Directory Intel** | Domain only | Full AD context extraction |
| **Performance** | ~5-10 endpoints/min | ~30-50 endpoints/min |
| **Report Integration** | Manual copy-paste | Automated PlexTrac format |

## 📦 Installation

### Quick Install (Recommended)
```bash
git clone https://github.com/lokii-git/ntlmsrh.git
cd ntlmsrh
chmod +x install.sh
sudo ./install.sh
```

### Manual Installation
```bash
# Clone the repository
git clone https://github.com/lokii-git/ntlmsrh.git
cd ntlmsrh

# Install dependencies (Python 3.6+)
pip3 install -r requirements.txt

# Install system-wide (optional)
sudo cp ntlmsrh.py /usr/local/bin/ntlmsrh
sudo chmod +x /usr/local/bin/ntlmsrh

# Test installation
ntlmsrh --help
```

## 🎯 Usage Examples

### Single Target Discovery
```bash
# Scan Exchange server
ntlmsrh mail.company.com

# Scan with detailed output
ntlmsrh 192.168.1.100 -v

# Fast scan with more threads
ntlmsrh webmail.company.com -t 20
```

### Bulk Reconnaissance
```bash
# Scan entire network segment
ntlmsrh 192.168.1.0/24

# Multiple targets from file
ntlmsrh targets.txt -t 25

# Generate reports for client delivery
ntlmsrh company-ips.txt -o ntlm_report.txt -j ntlm_data.json
```

### Advanced Scenarios
```bash
# Custom Exchange paths
ntlmsrh mail.company.com --paths exchange_paths.txt

# Quick timeout for large scans
ntlmsrh 10.0.0.0/16 --timeout 3 -t 30

# PlexTrac integration workflow
ntlmsrh targets.txt -o client_report.txt
# -> Auto-generates endpoints.txt for PlexTrac import
```

### Real-World Example Output
```
[*] Loading targets from: mail.company.com
[+] Found 1 targets to scan  
[*] Testing 77 paths per target
[*] Brute forcing 77 endpoints on mail.company.com

======================================================================
 NTLM Authentication Endpoints Discovered 
======================================================================

[NTLM] Endpoint #1: https://mail.company.com/ews/
   Status Code      : 401
   Server          : Microsoft-IIS/10.0
   AD Domain Name   : COMPANY
   Server Name      : EXCH01
   DNS Domain Name  : company.local
   FQDN            : exch01.company.local
   Parent DNS      : company.local
======================================================================

[+] Endpoints list saved to: endpoints.txt

[SUMMARY] Scan Results:
   Total Targets: 1
   NTLM Endpoints: 8
   Unique Domains: 1
   Unique Servers: 1
```

## 📊 Output

## 🔧 Technical Details

### NTLM Endpoint Coverage
NTLMSRH tests **77 carefully selected paths** covering:
- **Microsoft Exchange** (EWS, Autodiscover, OWA, ActiveSync, PowerShell)
- **SharePoint** (Sites, APIs, Web Services)  
- **IIS Applications** (ASP.NET, Web APIs, Virtual Directories)
- **Remote Services** (RPC, MAPI, Administrative interfaces)
- **Legacy Systems** (Older Exchange versions, custom apps)

### Intelligence Extraction
From each NTLM challenge response, NTLMSRH extracts:
- **NetBIOS Domain Name** - Internal AD domain (e.g., "COMPANY")
- **DNS Domain Name** - External domain (e.g., "company.local")  
- **Server Name** - NetBIOS computer name (e.g., "EXCH01")
- **FQDN** - Fully qualified domain name (e.g., "exch01.company.local")
- **Parent DNS Domain** - Root domain context
- **Server Software** - IIS version, application details

### Performance Characteristics
- **Scanning Speed**: 30-50 endpoints per minute (depending on network)
- **Thread Efficiency**: Optimal performance with 15-25 concurrent threads
- **Memory Usage**: <50MB for typical scans, <200MB for large CIDR ranges
- **Network Friendly**: Built-in retry logic and connection pooling
- **Timeout Management**: 5-second default timeout, configurable

### Output Formats

#### Console Output (Real-time)
```
[NTLM] Endpoint #1: https://mail.company.com/ews/
   Status Code      : 401
   Server          : Microsoft-IIS/10.0  
   AD Domain Name   : COMPANY
   Server Name      : EXCH01
   DNS Domain Name  : company.local
   FQDN            : exch01.company.local
   Parent DNS      : company.local
```

#### JSON Report (Automation)
```json
{
  "tool": "ntlmsrh",
  "version": "1.0.0",
  "timestamp": "2026-01-21T12:34:56",
  "summary": {
    "total_targets": 1,
    "total_endpoints": 8,
    "unique_domains": 1,
    "unique_servers": 1
  },
  "results": [{
    "url": "https://mail.company.com/ews/",
    "status_code": 401,
    "server_header": "Microsoft-IIS/10.0",
    "domain": "COMPANY",
    "server_name": "EXCH01",
    "dns_domain_name": "company.local",
    "fqdn": "exch01.company.local"
  }]
}
```

#### PlexTrac Integration (endpoints.txt)
```
# NTLM Authentication Endpoints Discovered
# Format: URL (IP) 
# Ready for PlexTrac 'Affected Assets' copy-paste

https://mail.company.com/ews/ (192.168.1.10)
https://mail.company.com/autodiscover/ (192.168.1.10)  
https://mail.company.com/Microsoft-Server-ActiveSync/ (192.168.1.10)
```

## 🛠️ Command Line Options

```
Usage: ntlmsrh.py [-h] [-t THREADS] [-o OUTPUT] [-j JSON] [--timeout TIMEOUT] [-v] [--paths PATHS] target

Arguments:
  target              Target IP, URL, CIDR range, or file containing targets

Options:
  -h, --help         Show help message and exit
  -t, --threads      Number of threads (default: 15)
  -o, --output       Save formatted text output to file
  -j, --json         Save JSON report to specified file  
  --timeout          Request timeout in seconds (default: 5)
  -v, --verbose      Verbose output with detailed progress
  --paths            Custom paths file (one per line)
```

## 🎯 Use Cases

### Penetration Testing
- **External reconnaissance** - Identify NTLM endpoints from outside the network
- **Internal enumeration** - Map internal Exchange and SharePoint infrastructure  
- **Domain intelligence** - Extract Active Directory context and server names
- **Reporting integration** - Generate client-ready reports with PlexTrac compatibility

### Red Team Operations  
- **Target identification** - Find authentication endpoints for credential attacks
- **Infrastructure mapping** - Understand internal network topology
- **Attack surface analysis** - Catalog all NTLM-enabled applications
- **Automation workflows** - JSON output for tool chaining and scripts

### Blue Team & Compliance
- **Asset discovery** - Inventory all NTLM endpoints across networks
- **Security assessment** - Identify exposed authentication interfaces
- **Compliance validation** - Document all external-facing NTLM services
- **Risk analysis** - Quantify NTLM exposure across environments

## 🙏 Credits & Attribution

**NTLMSRH v1.0** - A complete evolution of NTLM reconnaissance

- **Original NTLMRecon** by [@pwnfoo](https://github.com/pwnfoo) (Sachin Kamath)
- **Original NTLMScan concept** by [@nyxgeek](https://github.com/nyxgeek)
- **Enhanced and modernized** by [@lokii-git](https://github.com/lokii-git)

This project builds upon the excellent foundation laid by the original authors, incorporating modern development practices, enhanced functionality, and enterprise-ready features for today's penetration testing workflows.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**NTLMSRH v1.0** - Professional NTLM reconnaissance for modern penetration testing 🎯

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🔗 Related Tools

Part of the pentesting toolkit including:
- [Censys-Scan](../censys-scan/) - Censys intelligence gathering
- [IKE-Hunter](../ike-hunter/) - IKE/VPN vulnerability assessment
- [Shodan-Scan](../shodan-scan/) - Shodan reconnaissance

## 📈 Roadmap

- [ ] **IKEv2 Support**: Add IKEv2 endpoint detection
- [ ] **Kerberos Detection**: Identify Kerberos authentication
- [ ] **Certificate Analysis**: Extract and analyze SSL certificates
- [ ] **Vulnerability Checks**: Add specific NTLM vulnerability tests
- [ ] **Output Formats**: Add XML and HTML report formats
- [ ] **Integration APIs**: Add REST API for tool integration

---

**⚠️ Disclaimer**: This tool is for authorized penetration testing and security research only. Users are responsible for complying with applicable laws and regulations.