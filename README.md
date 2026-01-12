# Kali Linux MCP Server for Docker Desktop

A Model Context Protocol (MCP) server that exposes Kali Linux security testing tools to LLM clients via Docker Desktop's MCP Servers feature.

> **WARNING**: This tool is for **authorized security testing only**. Only use against systems you own or have explicit written permission to test. Unauthorized scanning or testing is illegal.

## Overview

This MCP server provides a safe, containerized interface to common penetration testing and security assessment tools from Kali Linux. It enables AI assistants to perform defensive security testing tasks through well-defined tool interfaces.

### Supported Tools

| Tool | MCP Name | Description |
|------|----------|-------------|
| Nmap | `port_scan` | Network discovery and port scanning |
| Nikto | `web_vuln_scan` | Web server vulnerability scanner |
| SQLMap | `sql_injection_test` | SQL injection detection and exploitation |
| ffuf | `directory_bruteforce` | Web fuzzer for directory/file discovery |
| Gobuster | `dns_bruteforce` | DNS subdomain enumeration |
| testssl.sh | `ssl_analysis` | SSL/TLS configuration analysis |
| Nuclei | `nuclei_scan` | Template-based vulnerability scanner |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Docker Desktop                              │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    MCP Client (LLM)                       │  │
│  │                                                           │  │
│  │  "Scan ports on target.example.com"                       │  │
│  └─────────────────────┬─────────────────────────────────────┘  │
│                        │ stdio (JSON-RPC)                        │
│                        ▼                                         │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              Kali Linux MCP Server Container              │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │            MCP Server (Python)                      │  │  │
│  │  │  - Tool registration                                │  │  │
│  │  │  - Input validation & sanitization                  │  │  │
│  │  │  - Command execution with timeouts                  │  │  │
│  │  │  - Output formatting                                │  │  │
│  │  └─────────────────────┬───────────────────────────────┘  │  │
│  │                        │                                   │  │
│  │  ┌─────────────────────▼───────────────────────────────┐  │  │
│  │  │              Kali Linux Tools                       │  │  │
│  │  │  nmap, nikto, sqlmap, ffuf, nuclei, etc.           │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### How It Works

1. **Docker Desktop** launches the container with stdio transport
2. **MCP Server** reads JSON-RPC requests from stdin
3. **Tool handlers** validate inputs and execute Kali tools
4. **Results** are returned as JSON-RPC responses to stdout
5. **Safety checks** prevent scanning of unauthorized targets

## Quick Start

### Prerequisites

- Docker Desktop with MCP Servers support
- Basic understanding of security testing concepts

### Installation

1. **Build the Docker image:**

```bash
docker build -t kali-mcp-server .
```

2. **Add to Docker Desktop MCP Servers:**

Open Docker Desktop → Settings → MCP Servers → Add Server

Use this configuration:

```json
{
  "kali-security": {
    "command": "docker",
    "args": [
      "run", "-i", "--rm",
      "--network", "host",
      "-e", "MCP_ALLOWED_TARGETS",
      "kali-mcp-server"
    ],
    "env": {
      "MCP_ALLOWED_TARGETS": "*.example.com,192.168.1.0/24"
    }
  }
}
```

3. **Restart Docker Desktop** to load the new MCP server.

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_ALLOWED_TARGETS` | Comma-separated list of allowed target patterns (supports wildcards and CIDR) | `*` (all - not recommended) |
| `MCP_BLOCKED_TARGETS` | Comma-separated list of blocked targets | `localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16` |
| `MCP_TIMEOUT` | Default command timeout in seconds | `300` |
| `MCP_RATE_LIMIT` | Minimum seconds between scans | `5` |
| `MCP_LOG_LEVEL` | Logging verbosity (DEBUG, INFO, WARNING, ERROR) | `INFO` |

### Target Allowlisting

For security, configure `MCP_ALLOWED_TARGETS` to only permit scanning of systems you own:

```bash
# Allow specific domain and subnet
MCP_ALLOWED_TARGETS="myapp.example.com,test.example.com,10.10.10.0/24"
```

## Tool Reference

### port_scan

Performs network port scanning using Nmap.

**Parameters:**
- `target` (required): Hostname or IP address
- `ports` (optional): Port specification (e.g., "80,443", "1-1000", default: top 1000)
- `scan_type` (optional): "quick", "standard", "comprehensive" (default: "standard")

**Example:**
```json
{
  "name": "port_scan",
  "arguments": {
    "target": "scanme.nmap.org",
    "ports": "22,80,443",
    "scan_type": "quick"
  }
}
```

### web_vuln_scan

Scans web servers for vulnerabilities using Nikto.

**Parameters:**
- `target` (required): URL of the web server
- `tuning` (optional): Nikto tuning options (1-9, default: "123")

**Example:**
```json
{
  "name": "web_vuln_scan",
  "arguments": {
    "target": "https://testphp.vulnweb.com",
    "tuning": "123"
  }
}
```

### sql_injection_test

Tests for SQL injection vulnerabilities using SQLMap.

**Parameters:**
- `target` (required): URL with parameter to test
- `level` (optional): Test level 1-5 (default: 1)
- `risk` (optional): Risk level 1-3 (default: 1)

**Example:**
```json
{
  "name": "sql_injection_test",
  "arguments": {
    "target": "http://testphp.vulnweb.com/listproducts.php?cat=1",
    "level": 2,
    "risk": 1
  }
}
```

### directory_bruteforce

Discovers hidden directories and files using ffuf.

**Parameters:**
- `target` (required): Base URL
- `wordlist` (optional): "small", "medium", "large" (default: "small")
- `extensions` (optional): File extensions to check (e.g., "php,html,txt")

**Example:**
```json
{
  "name": "directory_bruteforce",
  "arguments": {
    "target": "https://example.com",
    "wordlist": "medium",
    "extensions": "php,html"
  }
}
```

### ssl_analysis

Analyzes SSL/TLS configuration using testssl.sh.

**Parameters:**
- `target` (required): Hostname:port or URL
- `checks` (optional): "quick", "standard", "full" (default: "standard")

**Example:**
```json
{
  "name": "ssl_analysis",
  "arguments": {
    "target": "example.com:443",
    "checks": "standard"
  }
}
```

### nuclei_scan

Performs template-based vulnerability scanning using Nuclei.

**Parameters:**
- `target` (required): URL to scan
- `templates` (optional): Template categories (e.g., "cves,vulnerabilities")
- `severity` (optional): Minimum severity (info, low, medium, high, critical)

**Example:**
```json
{
  "name": "nuclei_scan",
  "arguments": {
    "target": "https://example.com",
    "severity": "medium"
  }
}
```

### dns_bruteforce

Enumerates DNS subdomains using Gobuster.

**Parameters:**
- `target` (required): Domain to enumerate
- `wordlist` (optional): "small", "medium", "large" (default: "small")

**Example:**
```json
{
  "name": "dns_bruteforce",
  "arguments": {
    "target": "example.com",
    "wordlist": "medium"
  }
}
```

## Extending with New Tools

### Adding a New Tool

1. Create a new tool module in `src/tools/`:

```python
# src/tools/my_tool.py
from typing import Any
from ..utils.validation import validate_target
from ..utils.execution import run_command

TOOL_DEFINITION = {
    "name": "my_new_tool",
    "description": "Description of what the tool does. REQUIRES AUTHORIZATION.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target to scan"
            }
        },
        "required": ["target"]
    }
}

async def execute(arguments: dict[str, Any]) -> str:
    target = validate_target(arguments["target"])

    cmd = ["mytool", "--target", target]
    result = await run_command(cmd, timeout=300)

    return result
```

2. Register the tool in `src/tools/__init__.py`

3. Rebuild the Docker image

## Security Considerations

### Built-in Protections

1. **Target Allowlisting**: Only scan pre-approved targets
2. **Blocked Networks**: Private/internal networks blocked by default
3. **Input Sanitization**: All inputs validated and sanitized
4. **Command Injection Prevention**: No shell execution, arguments passed as arrays
5. **Execution Timeouts**: All commands have enforced timeouts
6. **Rate Limiting**: Prevents rapid-fire scanning
7. **Non-root Execution**: Tools run as unprivileged user where possible

### What This Does NOT Protect Against

- Malicious use by authorized users
- Misconfiguration of allowed targets
- Zero-day vulnerabilities in underlying tools

## Legal and Ethical Notice

**This software is provided for AUTHORIZED SECURITY TESTING ONLY.**

By using this software, you agree that:

1. You will only scan systems you own or have explicit written permission to test
2. You understand that unauthorized scanning may be illegal in your jurisdiction
3. You accept full responsibility for how you use these tools
4. The authors are not liable for any misuse or damages

**Relevant Laws:**
- Computer Fraud and Abuse Act (CFAA) - United States
- Computer Misuse Act 1990 - United Kingdom
- Various local and international cybercrime laws

## Troubleshooting

### Container won't start

```bash
# Check Docker logs
docker logs <container_id>

# Test manually
docker run -it kali-mcp-server /bin/bash
```

### Tool returns timeout error

Increase the timeout in environment variables or use a quicker scan type.

### Target blocked error

Check your `MCP_ALLOWED_TARGETS` configuration. Ensure the target matches your allowlist patterns.

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.

## Acknowledgments

- Kali Linux team for the excellent security distribution
- MCP specification authors
- Authors of the underlying security tools
