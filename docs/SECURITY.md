# Security & Ethics Documentation

## Legal Disclaimer

**IMPORTANT: READ BEFORE USING THIS SOFTWARE**

This software provides security testing tools intended for **authorized defensive security testing only**. Using these tools against systems without explicit written permission is:

1. **Illegal** in most jurisdictions
2. **Unethical** regardless of intent
3. **Potentially harmful** to systems and data

By using this software, you acknowledge and agree that:

- You will only use these tools against systems you own or have explicit written permission to test
- You understand the legal implications of unauthorized security testing
- You accept full responsibility for your use of these tools
- The authors and contributors are not liable for any misuse

## Relevant Laws

### United States
- **Computer Fraud and Abuse Act (CFAA)** - 18 U.S.C. § 1030
  - Unauthorized access to computer systems is a federal crime
  - Penalties include fines and imprisonment

### European Union
- **Directive 2013/40/EU** on attacks against information systems
  - Criminalizes unauthorized access and interference

### United Kingdom
- **Computer Misuse Act 1990**
  - Unauthorized access is illegal
  - Unauthorized modification of data is illegal

### Other Jurisdictions
Most countries have similar cybercrime laws. Consult local regulations before performing any security testing.

---

## Authorization Requirements

### What Constitutes Authorization?

Valid authorization typically includes:

1. **Written Permission**
   - Explicit scope definition
   - Time boundaries
   - Contact information for emergencies
   - Signed by system owner or authorized representative

2. **Bug Bounty Programs**
   - Clear scope documentation
   - Safe harbor provisions
   - Published rules of engagement

3. **Penetration Testing Contracts**
   - Statement of Work (SOW)
   - Rules of Engagement (ROE)
   - Liability clauses
   - Emergency contacts

### What Does NOT Constitute Authorization?

- Verbal permission alone
- "I think they'd want me to test this"
- Open ports or misconfigurations
- "I'm doing them a favor"
- Academic research without explicit consent

---

## Built-in Security Controls

### Target Allowlisting

By default, this server blocks all internal/private network ranges:

```
- localhost (127.0.0.1, ::1)
- 10.0.0.0/8 (Class A private)
- 172.16.0.0/12 (Class B private)
- 192.168.0.0/16 (Class C private)
- 169.254.0.0/16 (Link-local)
- 224.0.0.0/4 (Multicast)
```

**For production use**, configure `MCP_ALLOWED_TARGETS` to explicitly list only authorized targets:

```bash
MCP_ALLOWED_TARGETS="mycompany.com,*.mycompany.com,192.0.2.0/24"
```

### Input Validation

All inputs are validated to prevent:

- Command injection attacks
- Path traversal
- Shell metacharacter exploitation
- Invalid target specifications

### Command Execution Safety

- All commands are executed as argument arrays (no shell interpretation)
- No `shell=True` subprocess execution
- Strict timeout enforcement
- Output size limits

### Rate Limiting

- Minimum 5 seconds between scans to the same target
- Configurable via `MCP_RATE_LIMIT` environment variable
- Prevents accidental DoS conditions

### Resource Limits

In production deployments, enforce container limits:

```yaml
deploy:
  resources:
    limits:
      cpus: '2'
      memory: 2G
```

---

## Responsible Use Guidelines

### Before Testing

1. **Verify Authorization**
   - Confirm written permission exists
   - Verify scope includes intended targets
   - Check time window is valid

2. **Understand Impact**
   - Some tests may cause service disruption
   - SQL injection tests can modify data
   - High-traffic scans may trigger security alerts

3. **Coordinate with Stakeholders**
   - Notify system owners of testing schedule
   - Provide contact information
   - Establish communication channel for emergencies

### During Testing

1. **Stay Within Scope**
   - Only test authorized systems
   - Respect defined boundaries
   - Stop immediately if asked

2. **Document Everything**
   - Record all actions taken
   - Timestamp findings
   - Preserve evidence appropriately

3. **Minimize Impact**
   - Use appropriate scan intensity
   - Avoid destructive actions
   - Stop if unintended effects occur

### After Testing

1. **Secure Findings**
   - Protect vulnerability data
   - Limit access to results
   - Follow responsible disclosure

2. **Report Professionally**
   - Clear, factual descriptions
   - Reproducible steps
   - Remediation recommendations

3. **Clean Up**
   - Remove test artifacts
   - Restore modified configurations
   - Delete temporary credentials

---

## Responsible Disclosure

If you discover vulnerabilities during authorized testing:

### DO:
- Report to the system owner first
- Provide clear reproduction steps
- Give reasonable time for remediation (typically 90 days)
- Coordinate disclosure timing
- Respect embargo requests

### DON'T:
- Publicly disclose before coordination
- Exploit vulnerabilities beyond proof-of-concept
- Access data beyond necessary verification
- Demand payment for withholding disclosure

---

## Security of This Tool

### Known Limitations

1. **Tool Accuracy**
   - False positives are possible
   - False negatives may occur
   - Results require human verification

2. **Container Security**
   - Running as non-root where possible
   - Some tools require elevated privileges
   - Container escape vulnerabilities may exist

3. **Network Exposure**
   - Uses host networking by default
   - Scan traffic may be logged by targets
   - Your IP will be visible to targets

### Hardening Recommendations

1. **Network Isolation**
   ```bash
   # Use VPN or isolated network for testing
   docker run --network custom-isolated-network ...
   ```

2. **Read-Only Filesystem**
   ```bash
   docker run --read-only --tmpfs /tmp ...
   ```

3. **Capability Dropping**
   ```bash
   docker run --cap-drop ALL --cap-add NET_RAW ...
   ```

4. **Resource Limits**
   ```bash
   docker run --memory 2g --cpus 2 ...
   ```

---

## Incident Response

If you suspect misuse of this tool:

1. **Preserve Logs**
   - Docker container logs
   - MCP server output
   - Network traffic logs

2. **Contact Information**
   - Local law enforcement for criminal matters
   - CERT/CSIRT for coordination
   - Legal counsel as appropriate

3. **Reporting Abuse**
   - Report to target organization
   - Report to hosting provider if applicable
   - Consider bug bounty platform reporting

---

## Acknowledgments

This project uses tools developed by the security community:

- **Nmap** - Gordon Lyon (Fyodor) and contributors
- **Nikto** - CIRT.net
- **SQLMap** - Bernardo Damele A.G. and Miroslav Stampar
- **ffuf** - joohoi
- **Gobuster** - OJ Reeves
- **testssl.sh** - Dirk Wetter
- **Nuclei** - ProjectDiscovery

Thank you to all security researchers who build tools for defensive security.

---

## Contact

For questions about responsible use of this tool, consult:

- Your organization's security team
- Legal counsel familiar with computer law
- Professional security certifications (OSCP, CEH, etc.) training materials
