# Security Policy

## Reporting Vulnerabilities in This MCP Server

If you discover a security vulnerability in the MCP server code itself (not in the underlying tools like nmap, nikto, etc.), please report it responsibly.

### How to Report

1. **Do NOT open a public issue** for security vulnerabilities
2. Use GitHub's **Private Vulnerability Reporting** feature:
   - Go to the Security tab → "Report a vulnerability"
3. Or open a draft security advisory in this repository

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Target**: Within 30 days for critical issues

### Scope

**In Scope:**
- Command injection in MCP server code
- Bypass of target allowlist/blocklist
- Authentication/authorization issues
- Information disclosure from the server
- Denial of service against the MCP server

**Out of Scope:**
- Vulnerabilities in underlying tools (nmap, nikto, sqlmap, etc.) - report these to their respective projects
- Issues requiring physical access
- Social engineering attacks
- Issues in dependencies (report to dependency maintainers)

## Security Best Practices for Users

1. **Always configure `MCP_ALLOWED_TARGETS`** - Don't leave it open
2. **Use read-only containers** in production
3. **Set resource limits** to prevent DoS
4. **Monitor container logs** for unexpected activity
5. **Keep the image updated** for security patches

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who report valid vulnerabilities (unless they prefer to remain anonymous).
