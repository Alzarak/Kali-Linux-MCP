"""
Security Tools Module

This module defines and exposes all available security testing tools
through the MCP interface.

Each tool follows a standard pattern:
1. TOOL_DEFINITION: JSON schema describing the tool
2. execute(): Async function that runs the tool

WARNING: These tools are for authorized security testing only.
"""

import logging
from typing import Any

from .port_scan import TOOL_DEFINITION as PORT_SCAN_DEF, execute as port_scan_execute
from .web_vuln_scan import TOOL_DEFINITION as WEB_VULN_DEF, execute as web_vuln_execute
from .sql_injection import TOOL_DEFINITION as SQL_INJECTION_DEF, execute as sql_injection_execute
from .directory_bruteforce import TOOL_DEFINITION as DIR_BRUTE_DEF, execute as dir_brute_execute
from .ssl_analysis import TOOL_DEFINITION as SSL_ANALYSIS_DEF, execute as ssl_analysis_execute
from .nuclei_scan import TOOL_DEFINITION as NUCLEI_SCAN_DEF, execute as nuclei_scan_execute
from .dns_bruteforce import TOOL_DEFINITION as DNS_BRUTE_DEF, execute as dns_brute_execute

logger = logging.getLogger(__name__)

# Registry of all available tools
TOOLS: dict[str, dict[str, Any]] = {
    "port_scan": {
        **PORT_SCAN_DEF,
        "_execute": port_scan_execute,
    },
    "web_vuln_scan": {
        **WEB_VULN_DEF,
        "_execute": web_vuln_execute,
    },
    "sql_injection_test": {
        **SQL_INJECTION_DEF,
        "_execute": sql_injection_execute,
    },
    "directory_bruteforce": {
        **DIR_BRUTE_DEF,
        "_execute": dir_brute_execute,
    },
    "ssl_analysis": {
        **SSL_ANALYSIS_DEF,
        "_execute": ssl_analysis_execute,
    },
    "nuclei_scan": {
        **NUCLEI_SCAN_DEF,
        "_execute": nuclei_scan_execute,
    },
    "dns_bruteforce": {
        **DNS_BRUTE_DEF,
        "_execute": dns_brute_execute,
    },
}


async def execute_tool(name: str, arguments: dict[str, Any]) -> str:
    """
    Execute a tool by name with the given arguments.

    Args:
        name: The tool name
        arguments: Dictionary of arguments to pass to the tool

    Returns:
        String result from the tool execution

    Raises:
        ValueError: If the tool name is not recognized
        Other exceptions may be raised by individual tools
    """
    if name not in TOOLS:
        raise ValueError(f"Unknown tool: {name}. Available tools: {', '.join(TOOLS.keys())}")

    tool = TOOLS[name]
    execute_fn = tool["_execute"]

    logger.info(f"Executing tool: {name}")
    return await execute_fn(arguments)


__all__ = ["TOOLS", "execute_tool"]
