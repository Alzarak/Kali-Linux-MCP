"""
Kali Linux MCP Server - Main Entry Point

This module implements the MCP server that exposes Kali Linux security
tools to LLM clients via the Model Context Protocol.

WARNING: For authorized security testing only.
"""

import asyncio
import logging
import os
import sys
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Tool,
    TextContent,
    CallToolResult,
)

from .tools import TOOLS, execute_tool
from .utils.logging import setup_logging

# Initialize logging - all logs go to stderr, stdout is for MCP protocol
logger = setup_logging()


def create_server() -> Server:
    """Create and configure the MCP server instance."""
    server = Server("kali-security-tools")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        """Return the list of available security tools."""
        logger.debug("Client requested tool list")
        return [
            Tool(
                name=tool["name"],
                description=tool["description"],
                inputSchema=tool["inputSchema"],
            )
            for tool in TOOLS.values()
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
        """Execute a security tool with the given arguments."""
        logger.info(f"Tool call received: {name}")
        logger.debug(f"Arguments: {arguments}")

        try:
            # Execute the tool and get results
            result = await execute_tool(name, arguments)

            logger.info(f"Tool {name} completed successfully")

            return CallToolResult(
                content=[TextContent(type="text", text=result)],
                isError=False,
            )
        except ValueError as e:
            # Input validation errors
            logger.warning(f"Validation error for {name}: {e}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Validation Error: {str(e)}")],
                isError=True,
            )
        except PermissionError as e:
            # Target not allowed
            logger.warning(f"Permission denied for {name}: {e}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Permission Denied: {str(e)}")],
                isError=True,
            )
        except TimeoutError as e:
            # Command timeout
            logger.warning(f"Timeout for {name}: {e}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Timeout: {str(e)}")],
                isError=True,
            )
        except Exception as e:
            # Unexpected errors
            logger.error(f"Unexpected error in {name}: {e}", exc_info=True)
            return CallToolResult(
                content=[TextContent(type="text", text=f"Error: {str(e)}")],
                isError=True,
            )

    return server


async def main() -> None:
    """Main entry point for the MCP server."""
    logger.info("Kali Linux MCP Server starting")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Log level: {os.environ.get('MCP_LOG_LEVEL', 'INFO')}")

    # Log configuration
    allowed = os.environ.get("MCP_ALLOWED_TARGETS", "")
    blocked = os.environ.get("MCP_BLOCKED_TARGETS", "")
    logger.info(f"Allowed targets: {allowed if allowed else 'ALL (not recommended)'}")
    logger.info(f"Blocked targets: {blocked if blocked else 'default internal networks'}")

    server = create_server()

    # Run the server using stdio transport
    async with stdio_server() as (read_stream, write_stream):
        logger.info("MCP server ready, awaiting client connection")
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
