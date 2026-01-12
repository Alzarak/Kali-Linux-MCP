"""
Kali Linux MCP Server - Main Entry Point

Run with: python -m src
"""

import asyncio
from .server import main

if __name__ == "__main__":
    asyncio.run(main())
