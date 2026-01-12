"""
Port Scan Tool (Nmap)

Performs network port scanning using Nmap to discover open ports
and running services on target systems.

WARNING: Only use against systems you have explicit authorization to scan.
Port scanning without permission may be illegal in your jurisdiction.
"""

from typing import Any

from ..utils.validation import validate_target, validate_port_spec, validate_wordlist_choice
from ..utils.execution import run_command, format_command_output
from ..utils.rate_limiter import get_rate_limiter

TOOL_DEFINITION = {
    "name": "port_scan",
    "description": """Perform network port scanning using Nmap.

⚠️ AUTHORIZATION REQUIRED: Only scan systems you own or have written permission to test.

This tool discovers:
- Open TCP/UDP ports
- Running services and versions
- Operating system information (comprehensive scan)

Scan types:
- quick: Fast scan of top 100 ports (fastest, ~30s)
- standard: Default scan of top 1000 ports (~2-5min)
- comprehensive: Full scan with version detection (~10-30min)""",
    "inputSchema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target hostname or IP address to scan. Must be a system you have authorization to test."
            },
            "ports": {
                "type": "string",
                "description": "Port specification. Examples: '22,80,443', '1-1000', 'T:80,443,U:53'. Default: top 1000 ports."
            },
            "scan_type": {
                "type": "string",
                "enum": ["quick", "standard", "comprehensive"],
                "description": "Scan intensity level. 'quick' is fastest, 'comprehensive' is most thorough but slowest."
            }
        },
        "required": ["target"]
    }
}

# Scan type configurations
SCAN_CONFIGS = {
    "quick": {
        "args": ["-T4", "-F"],  # Fast timing, top 100 ports
        "timeout": 120,
        "description": "Quick scan - top 100 ports"
    },
    "standard": {
        "args": ["-T3", "-sV"],  # Normal timing, version detection
        "timeout": 300,
        "description": "Standard scan - top 1000 ports with version detection"
    },
    "comprehensive": {
        "args": ["-T3", "-sV", "-sC", "-O", "--top-ports", "5000"],
        "timeout": 1800,
        "description": "Comprehensive scan - top 5000 ports, version detection, scripts, OS detection"
    }
}


async def execute(arguments: dict[str, Any]) -> str:
    """
    Execute an Nmap port scan.

    Args:
        arguments: Dictionary containing:
            - target (required): Hostname or IP to scan
            - ports (optional): Port specification
            - scan_type (optional): quick, standard, or comprehensive

    Returns:
        Formatted scan results
    """
    # Validate target
    target = validate_target(arguments["target"])

    # Get scan configuration
    scan_type = arguments.get("scan_type", "standard")
    if scan_type not in SCAN_CONFIGS:
        scan_type = "standard"

    config = SCAN_CONFIGS[scan_type]

    # Rate limit
    rate_limiter = get_rate_limiter()
    await rate_limiter.acquire(target)

    # Build command
    cmd = ["nmap"]
    cmd.extend(config["args"])

    # Add custom ports if specified
    if "ports" in arguments and arguments["ports"]:
        ports = validate_port_spec(arguments["ports"])
        cmd.extend(["-p", ports])

    # Output format
    cmd.extend(["-oN", "-"])  # Normal output to stdout

    # Add target
    cmd.append(target)

    # Execute scan
    result = await run_command(cmd, timeout=config["timeout"])

    # Format output
    output_parts = [
        f"Nmap Port Scan Results",
        f"Target: {target}",
        f"Scan Type: {config['description']}",
        "",
        "=" * 60,
        ""
    ]

    if result.success:
        output_parts.append(result.stdout)
    else:
        output_parts.append(f"Scan completed with warnings (exit code: {result.return_code})")
        output_parts.append("")
        output_parts.append(result.stdout)
        if result.stderr:
            output_parts.append("")
            output_parts.append("--- Warnings ---")
            output_parts.append(result.stderr)

    return "\n".join(output_parts)
