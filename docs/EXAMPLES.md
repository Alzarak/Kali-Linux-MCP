# Kali Linux MCP Server - Usage Examples

This document provides examples of how LLM clients interact with the Kali Linux MCP server.

## Overview

When connected through Docker Desktop MCP Servers, an LLM client can request security scans using the tools exposed by this server. Each request follows the MCP tool call format.

---

## Example 1: Port Scanning

### User Request (to LLM)
> "Can you scan scanme.nmap.org to see what ports are open?"

### MCP Tool Call (from LLM to Server)
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "port_scan",
    "arguments": {
      "target": "scanme.nmap.org",
      "scan_type": "standard"
    }
  }
}
```

### MCP Response (from Server)
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Nmap Port Scan Results\nTarget: scanme.nmap.org\nScan Type: Standard scan - top 1000 ports with version detection\n\n============================================================\n\nStarting Nmap 7.94 ( https://nmap.org )\nNmap scan report for scanme.nmap.org (45.33.32.156)\nHost is up (0.089s latency).\n\nPORT      STATE    SERVICE      VERSION\n22/tcp    open     ssh          OpenSSH 6.6.1p1\n80/tcp    open     http         Apache httpd 2.4.7\n9929/tcp  open     nping-echo   Nping echo\n31337/tcp open     tcpwrapped\n\nService detection performed.\nNmap done: 1 IP address (1 host up) scanned in 12.34 seconds"
      }
    ],
    "isError": false
  }
}
```

---

## Example 2: Web Vulnerability Scan

### User Request
> "Check testphp.vulnweb.com for web vulnerabilities"

### MCP Tool Call
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "web_vuln_scan",
    "arguments": {
      "target": "http://testphp.vulnweb.com",
      "tuning": "123"
    }
  }
}
```

### MCP Response
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Nikto Web Vulnerability Scan Results\nTarget: http://testphp.vulnweb.com\nTuning: 123\n\n============================================================\n\n- Nikto v2.5.0\n---------------------------------------------------------------------------\n+ Target IP:          44.228.249.3\n+ Target Hostname:    testphp.vulnweb.com\n+ Target Port:        80\n+ Start Time:         2024-01-15 10:30:00\n---------------------------------------------------------------------------\n+ Server: nginx/1.19.0\n+ /: The anti-clickjacking X-Frame-Options header is not present.\n+ /: The X-Content-Type-Options header is not set.\n+ /admin/: This might be interesting.\n+ /backup/: Directory indexing found.\n+ OSVDB-3092: /test.php: This might be interesting.\n+ 7915 requests: 0 error(s) and 12 item(s) reported on remote host\n+ End Time: 2024-01-15 10:35:23\n---------------------------------------------------------------------------\n\n============================================================\nNote: Review findings carefully. Not all items are vulnerabilities."
      }
    ],
    "isError": false
  }
}
```

---

## Example 3: SQL Injection Test

### User Request
> "Test this URL for SQL injection: http://testphp.vulnweb.com/listproducts.php?cat=1"

### MCP Tool Call
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "sql_injection_test",
    "arguments": {
      "target": "http://testphp.vulnweb.com/listproducts.php?cat=1",
      "level": 2,
      "risk": 1
    }
  }
}
```

### MCP Response
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "SQLMap SQL Injection Test Results\nTarget: http://testphp.vulnweb.com/listproducts.php?cat=1\nLevel: 2, Risk: 1\nTechniques: BEUST\n\n============================================================\n\n[INFO] testing connection to the target URL\n[INFO] testing if the target URL is stable\n[INFO] target URL is stable\n[INFO] testing if GET parameter 'cat' is dynamic\n[INFO] GET parameter 'cat' appears to be dynamic\n[INFO] heuristic (basic) test shows that GET parameter 'cat' might be injectable\n[INFO] testing for SQL injection on GET parameter 'cat'\n[INFO] GET parameter 'cat' is 'MySQL >= 5.0 AND error-based' injectable\n[INFO] GET parameter 'cat' is 'MySQL >= 5.0 OR error-based' injectable\n[INFO] GET parameter 'cat' is 'MySQL >= 5.0 UNION query (NULL)' injectable\n\nsqlmap identified the following injection point(s):\n---\nParameter: cat (GET)\n    Type: error-based\n    Title: MySQL >= 5.0 AND error-based\n    Payload: cat=1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT...\n\n    Type: UNION query\n    Title: MySQL UNION query (NULL) - 11 columns\n    Payload: cat=-7833 UNION ALL SELECT NULL,NULL,CONCAT(0x717a...),...\n---\n[INFO] the back-end DBMS is MySQL\nback-end DBMS: MySQL >= 5.0\n\n============================================================\n⚠️ If vulnerabilities found, follow responsible disclosure practices."
      }
    ],
    "isError": false
  }
}
```

---

## Example 4: Directory Discovery

### User Request
> "Find hidden directories on https://example.com"

### MCP Tool Call
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "directory_bruteforce",
    "arguments": {
      "target": "https://example.com",
      "wordlist": "medium",
      "extensions": "php,html,txt"
    }
  }
}
```

### MCP Response
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "ffuf Directory Bruteforce Results\nTarget: https://example.com/\nWordlist: medium (/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt)\n\n============================================================\n\nDiscovered paths:\n\nURL                                                          Status   Size      \n--------------------------------------------------------------------------------\nhttps://example.com/admin                                    301      154       \nhttps://example.com/admin.php                                200      4521      \nhttps://example.com/backup                                   403      162       \nhttps://example.com/config                                   301      156       \nhttps://example.com/images                                   301      156       \nhttps://example.com/robots.txt                               200      128       \nhttps://example.com/sitemap.xml                              200      2341"
      }
    ],
    "isError": false
  }
}
```

---

## Example 5: SSL/TLS Analysis

### User Request
> "Analyze the SSL configuration of github.com"

### MCP Tool Call
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "ssl_analysis",
    "arguments": {
      "target": "github.com:443",
      "checks": "standard"
    }
  }
}
```

### MCP Response
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "testssl.sh SSL/TLS Analysis Results\nTarget: github.com:443\nCheck Level: Standard - protocols, ciphers, common vulnerabilities\n\n============================================================\n\n Testing protocols via native openssl\n\n SSLv2      not offered (OK)\n SSLv3      not offered (OK)\n TLS 1      not offered\n TLS 1.1    not offered\n TLS 1.2    offered (OK)\n TLS 1.3    offered (OK)\n\n Testing cipher categories\n\n NULL ciphers                      not offered (OK)\n Anonymous NULL Ciphers            not offered (OK)\n Export ciphers                    not offered (OK)\n LOW (64 bit + DES)                not offered (OK)\n Weak 128 bit ciphers              not offered (OK)\n 3DES                              not offered (OK)\n High (AES+CAMELLIA, no AEAD)      offered\n Strong (AEAD ciphers)             offered (OK)\n\n Testing vulnerabilities\n\n Heartbleed (CVE-2014-0160)        not vulnerable (OK)\n CCS (CVE-2014-0224)               not vulnerable (OK)\n Ticketbleed (CVE-2016-9244)       not vulnerable (OK)\n ROBOT                             not vulnerable (OK)\n Secure Renegotiation              supported (OK)\n\n Overall Rating: A+\n\n============================================================\nLegend: Rating A-F (A+ is best). Review any findings marked VULNERABLE."
      }
    ],
    "isError": false
  }
}
```

---

## Example 6: Nuclei Template Scan

### User Request
> "Run a CVE vulnerability scan on https://testphp.vulnweb.com"

### MCP Tool Call
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "tools/call",
  "params": {
    "name": "nuclei_scan",
    "arguments": {
      "target": "https://testphp.vulnweb.com",
      "templates": "cves,vulnerabilities",
      "severity": "medium"
    }
  }
}
```

### MCP Response
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Nuclei Vulnerability Scan Results\nTarget: https://testphp.vulnweb.com\nTemplates: cves, vulnerabilities\nMinimum Severity: medium\n\n============================================================\n\nFound 5 potential issue(s):\n\n  • [medium] [http] CVE-2019-11043: PHP-FPM Remote Code Execution\n  • [high] [http] sql-injection: SQL Injection in listproducts.php\n  • [medium] [http] xss-reflected: Reflected XSS in search.php\n  • [medium] [http] directory-listing: Directory listing enabled on /images/\n  • [critical] [http] CVE-2021-41773: Apache Path Traversal\n\n============================================================\n⚠️ Review findings carefully. Verify vulnerabilities before reporting."
      }
    ],
    "isError": false
  }
}
```

---

## Example 7: DNS Subdomain Enumeration

### User Request
> "Find subdomains for example.com"

### MCP Tool Call
```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "tools/call",
  "params": {
    "name": "dns_bruteforce",
    "arguments": {
      "target": "example.com",
      "wordlist": "small",
      "show_ips": true
    }
  }
}
```

### MCP Response
```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Gobuster DNS Subdomain Enumeration Results\nTarget Domain: example.com\nWordlist: small\n\n============================================================\n\nFound 8 subdomain(s):\n\n  • api.example.com [93.184.216.34]\n  • blog.example.com [93.184.216.35]\n  • dev.example.com [93.184.216.36]\n  • mail.example.com [93.184.216.37]\n  • staging.example.com [93.184.216.38]\n  • test.example.com [93.184.216.39]\n  • vpn.example.com [93.184.216.40]\n  • www.example.com [93.184.216.34]\n\n============================================================\nNote: Some subdomains may be blocked by DNS providers or firewalls."
      }
    ],
    "isError": false
  }
}
```

---

## Example 8: Error Handling - Blocked Target

### User Request
> "Scan 192.168.1.1 for open ports"

### MCP Tool Call
```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "method": "tools/call",
  "params": {
    "name": "port_scan",
    "arguments": {
      "target": "192.168.1.1"
    }
  }
}
```

### MCP Response (Error)
```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Permission Denied: Target '192.168.1.1' is in blocked network '192.168.0.0/16'"
      }
    ],
    "isError": true
  }
}
```

---

## Example 9: Listing Available Tools

### MCP Request
```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "method": "tools/list",
  "params": {}
}
```

### MCP Response
```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "result": {
    "tools": [
      {
        "name": "port_scan",
        "description": "Perform network port scanning using Nmap.\n\n⚠️ AUTHORIZATION REQUIRED...",
        "inputSchema": {
          "type": "object",
          "properties": {
            "target": {"type": "string", "description": "Target hostname or IP..."},
            "ports": {"type": "string", "description": "Port specification..."},
            "scan_type": {"type": "string", "enum": ["quick", "standard", "comprehensive"]}
          },
          "required": ["target"]
        }
      },
      {
        "name": "web_vuln_scan",
        "description": "Scan web servers for vulnerabilities using Nikto...",
        "inputSchema": {...}
      },
      {
        "name": "sql_injection_test",
        "description": "Test web application parameters for SQL injection...",
        "inputSchema": {...}
      },
      {
        "name": "directory_bruteforce",
        "description": "Discover hidden directories and files...",
        "inputSchema": {...}
      },
      {
        "name": "ssl_analysis",
        "description": "Analyze SSL/TLS configuration...",
        "inputSchema": {...}
      },
      {
        "name": "nuclei_scan",
        "description": "Perform template-based vulnerability scanning...",
        "inputSchema": {...}
      },
      {
        "name": "dns_bruteforce",
        "description": "Enumerate DNS subdomains...",
        "inputSchema": {...}
      }
    ]
  }
}
```

---

## Testing Tips

### Authorized Test Targets

For testing, use these intentionally vulnerable targets:

1. **scanme.nmap.org** - Nmap's official test target for port scanning
2. **testphp.vulnweb.com** - Acunetix's vulnerable PHP application
3. **testhtml5.vulnweb.com** - Acunetix's HTML5 test site
4. **testaspnet.vulnweb.com** - Acunetix's ASP.NET test site

### Local Testing with Docker Compose

```bash
# Start the MCP server in development mode
docker compose up -d

# Optional: Start DVWA for local testing
docker compose --profile testing up -d

# View logs
docker logs -f kali-mcp-dev
```

### Manual Tool Testing

```bash
# Run container interactively
docker run -it --rm kali-mcp-server /bin/bash

# Test tools directly
nmap -T4 -F scanme.nmap.org
nikto -h http://testphp.vulnweb.com
```
