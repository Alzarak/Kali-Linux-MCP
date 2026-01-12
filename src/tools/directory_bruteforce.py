"""
Directory Bruteforce Tool (ffuf)

Discovers hidden directories and files on web servers using ffuf,
a fast web fuzzer.

WARNING: Only use against web servers you have explicit authorization to test.
Directory bruteforcing without permission may be illegal and can cause server load.
"""

from typing import Any
from urllib.parse import urlparse

from ..utils.validation import validate_url, validate_wordlist_choice, sanitize_input
from ..utils.execution import run_command
from ..utils.rate_limiter import get_rate_limiter

TOOL_DEFINITION = {
    "name": "directory_bruteforce",
    "description": """Discover hidden directories and files on web servers using ffuf.

⚠️ AUTHORIZATION REQUIRED: Only scan web servers you own or have written permission to test.

This tool:
- Bruteforces directory and file names
- Can discover hidden admin panels, backup files, etc.
- Uses configurable wordlists

Wordlist sizes:
- small: ~5,000 entries (fastest, ~1-2 min)
- medium: ~20,000 entries (~5-10 min)
- large: ~200,000 entries (~30+ min)

Extensions option allows checking for specific file types.""",
    "inputSchema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target base URL (http:// or https://). Must be a server you have authorization to test."
            },
            "wordlist": {
                "type": "string",
                "enum": ["small", "medium", "large"],
                "description": "Wordlist size. 'small' is fastest, 'large' most thorough. Default: small"
            },
            "extensions": {
                "type": "string",
                "description": "Comma-separated file extensions to check (e.g., 'php,html,txt'). Optional."
            },
            "recursive": {
                "type": "boolean",
                "description": "Enable recursive scanning of discovered directories. Default: false"
            }
        },
        "required": ["target"]
    }
}

# Wordlist paths (standard Kali Linux locations)
WORDLISTS = {
    "small": "/usr/share/wordlists/dirb/common.txt",
    "medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "large": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
}

# Timeout per wordlist size
TIMEOUTS = {
    "small": 180,
    "medium": 600,
    "large": 1800,
}


def validate_extensions(extensions: str) -> str:
    """Validate and sanitize file extensions."""
    if not extensions:
        return ""

    # Split and clean
    exts = []
    for ext in extensions.split(","):
        ext = ext.strip().lower()
        # Remove leading dots
        ext = ext.lstrip(".")
        # Only allow alphanumeric
        if ext and ext.isalnum() and len(ext) <= 10:
            exts.append(ext)

    if not exts:
        raise ValueError("No valid extensions provided")

    return ",".join(exts)


async def execute(arguments: dict[str, Any]) -> str:
    """
    Execute a ffuf directory bruteforce scan.

    Args:
        arguments: Dictionary containing:
            - target (required): Base URL to scan
            - wordlist (optional): small, medium, or large
            - extensions (optional): File extensions to check
            - recursive (optional): Enable recursive scanning

    Returns:
        Formatted scan results
    """
    # Validate URL
    target_url = validate_url(arguments["target"])

    # Ensure URL ends with /
    if not target_url.endswith("/"):
        target_url += "/"

    # Parse URL to get host for rate limiting
    parsed = urlparse(target_url)
    hostname = parsed.hostname

    # Rate limit
    rate_limiter = get_rate_limiter()
    await rate_limiter.acquire(hostname)

    # Get wordlist
    wordlist_choice = arguments.get("wordlist", "small")
    wordlist_choice = validate_wordlist_choice(wordlist_choice, list(WORDLISTS.keys()))
    wordlist_path = WORDLISTS[wordlist_choice]

    timeout = TIMEOUTS[wordlist_choice]

    # Build ffuf URL with FUZZ keyword
    fuzz_url = target_url + "FUZZ"

    # Build command
    cmd = [
        "ffuf",
        "-u", fuzz_url,
        "-w", wordlist_path,
        "-t", "50",  # 50 threads
        "-timeout", "10",  # 10 second request timeout
        "-mc", "200,204,301,302,307,308,401,403,405,500",  # Match these status codes
        "-ac",  # Auto-calibrate filtering
        "-o", "-",  # Output to stdout
        "-of", "csv",  # CSV output format
        "-noninteractive",
    ]

    # Add extensions if specified
    if "extensions" in arguments and arguments["extensions"]:
        extensions = validate_extensions(arguments["extensions"])
        cmd.extend(["-e", extensions])

    # Add recursion if enabled
    if arguments.get("recursive", False):
        cmd.extend(["-recursion", "-recursion-depth", "2"])

    # Execute scan
    result = await run_command(cmd, timeout=timeout)

    # Format output
    output_parts = [
        f"ffuf Directory Bruteforce Results",
        f"Target: {target_url}",
        f"Wordlist: {wordlist_choice} ({wordlist_path})",
        "",
        "=" * 60,
        ""
    ]

    if result.stdout:
        # Parse CSV output
        lines = result.stdout.strip().split("\n")
        if len(lines) > 1:  # Has header + results
            output_parts.append("Discovered paths:")
            output_parts.append("")
            output_parts.append(f"{'URL':<60} {'Status':<8} {'Size':<10}")
            output_parts.append("-" * 80)

            for line in lines[1:]:  # Skip header
                parts = line.split(",")
                if len(parts) >= 5:
                    url = parts[1] if len(parts) > 1 else ""
                    status = parts[4] if len(parts) > 4 else ""
                    size = parts[5] if len(parts) > 5 else ""
                    if url:
                        output_parts.append(f"{url:<60} {status:<8} {size:<10}")
        else:
            output_parts.append("No directories or files discovered.")
    else:
        output_parts.append("No results returned. The scan may have been filtered or no paths found.")

    if result.stderr and "error" in result.stderr.lower():
        output_parts.append("")
        output_parts.append("--- Errors ---")
        output_parts.append(result.stderr)

    return "\n".join(output_parts)
