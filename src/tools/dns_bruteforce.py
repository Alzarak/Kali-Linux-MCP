"""
DNS Subdomain Bruteforce Tool (Gobuster)

Enumerates DNS subdomains using Gobuster in DNS mode.

WARNING: Only use against domains you have explicit authorization to test.
DNS enumeration without permission may violate terms of service.
"""

from typing import Any

from ..utils.validation import validate_target, validate_wordlist_choice
from ..utils.execution import run_command
from ..utils.rate_limiter import get_rate_limiter

TOOL_DEFINITION = {
    "name": "dns_bruteforce",
    "description": """Enumerate DNS subdomains using Gobuster DNS mode.

⚠️ AUTHORIZATION REQUIRED: Only enumerate domains you own or have written permission to test.

This tool discovers subdomains by:
- Bruteforcing common subdomain names
- Verifying DNS resolution
- Identifying active hosts

Wordlist sizes:
- small: ~5,000 entries (fastest, ~1-2 min)
- medium: ~20,000 entries (~5-10 min)
- large: ~100,000 entries (~20+ min)

Note: Results depend on DNS resolver response. Some hosts may block bruteforce attempts.""",
    "inputSchema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target domain (e.g., 'example.com'). Must be a domain you have authorization to test."
            },
            "wordlist": {
                "type": "string",
                "enum": ["small", "medium", "large"],
                "description": "Wordlist size. 'small' is fastest. Default: small"
            },
            "resolver": {
                "type": "string",
                "description": "Custom DNS resolver IP (e.g., '8.8.8.8'). Default: system resolver"
            },
            "show_ips": {
                "type": "boolean",
                "description": "Include resolved IP addresses in output. Default: true"
            }
        },
        "required": ["target"]
    }
}

# Wordlist paths
WORDLISTS = {
    "small": "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "medium": "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "large": "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
}

# Fallback wordlist if seclists isn't available
FALLBACK_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

# Timeouts per wordlist
TIMEOUTS = {
    "small": 300,
    "medium": 900,
    "large": 2400,
}


def validate_domain(domain: str) -> str:
    """Validate and clean a domain name."""
    domain = domain.strip().lower()

    # Remove any protocol prefix
    if domain.startswith("http://"):
        domain = domain[7:]
    elif domain.startswith("https://"):
        domain = domain[8:]

    # Remove trailing slash and path
    domain = domain.split("/")[0]

    # Remove www. prefix if present
    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def validate_resolver(resolver: str) -> str:
    """Validate DNS resolver IP."""
    import socket

    if not resolver:
        return ""

    resolver = resolver.strip()

    # Basic IP validation
    try:
        socket.inet_aton(resolver)
        return resolver
    except socket.error:
        raise ValueError(f"Invalid resolver IP: {resolver}")


async def execute(arguments: dict[str, Any]) -> str:
    """
    Execute a Gobuster DNS subdomain bruteforce.

    Args:
        arguments: Dictionary containing:
            - target (required): Domain to enumerate
            - wordlist (optional): small, medium, or large
            - resolver (optional): Custom DNS resolver
            - show_ips (optional): Show resolved IPs

    Returns:
        Formatted enumeration results
    """
    # Validate and clean domain
    domain = validate_domain(arguments["target"])
    validate_target(domain)

    # Rate limit
    rate_limiter = get_rate_limiter()
    await rate_limiter.acquire(domain)

    # Get wordlist
    wordlist_choice = arguments.get("wordlist", "small")
    wordlist_choice = validate_wordlist_choice(wordlist_choice, list(WORDLISTS.keys()))
    wordlist_path = WORDLISTS[wordlist_choice]

    timeout = TIMEOUTS[wordlist_choice]

    # Build command
    cmd = [
        "gobuster", "dns",
        "-d", domain,
        "-w", wordlist_path,
        "-t", "50",  # 50 threads
        "-q",  # Quiet mode
        "--timeout", "5s",  # Per-request timeout
    ]

    # Add resolver if specified
    if "resolver" in arguments and arguments["resolver"]:
        resolver = validate_resolver(arguments["resolver"])
        if resolver:
            cmd.extend(["-r", resolver])

    # Show IPs option
    if arguments.get("show_ips", True):
        cmd.append("-i")  # Show IP addresses

    # Execute enumeration
    result = await run_command(cmd, timeout=timeout)

    # Format output
    output_parts = [
        f"Gobuster DNS Subdomain Enumeration Results",
        f"Target Domain: {domain}",
        f"Wordlist: {wordlist_choice}",
        "",
        "=" * 60,
        ""
    ]

    if result.stdout:
        lines = result.stdout.strip().split("\n")
        found_subdomains = [l for l in lines if l.strip() and not l.startswith("=")]

        if found_subdomains:
            output_parts.append(f"Found {len(found_subdomains)} subdomain(s):")
            output_parts.append("")
            for subdomain in sorted(found_subdomains):
                output_parts.append(f"  • {subdomain}")
        else:
            output_parts.append("No subdomains discovered with the selected wordlist.")
    else:
        output_parts.append("No subdomains discovered with the selected wordlist.")

    if result.stderr:
        # Filter out progress messages
        errors = [l for l in result.stderr.split("\n")
                  if "error" in l.lower() or "warning" in l.lower()]
        if errors:
            output_parts.append("")
            output_parts.append("--- Warnings ---")
            output_parts.extend(errors)

    output_parts.append("")
    output_parts.append("=" * 60)
    output_parts.append("Note: Some subdomains may be blocked by DNS providers or firewalls.")

    return "\n".join(output_parts)
