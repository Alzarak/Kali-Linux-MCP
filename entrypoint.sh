#!/bin/bash
# Kali Linux MCP Server Entrypoint
# This script initializes the environment and starts the MCP server

set -e

# Validate required environment is set
if [ -z "$MCP_ALLOWED_TARGETS" ] && [ "$MCP_LOG_LEVEL" != "DEBUG" ]; then
    echo "WARNING: MCP_ALLOWED_TARGETS is not set. All external targets will be allowed." >&2
    echo "For production use, set MCP_ALLOWED_TARGETS to limit scanning scope." >&2
fi

# Log startup information to stderr (stdout is reserved for MCP protocol)
echo "Kali Linux MCP Server starting..." >&2
echo "Log level: ${MCP_LOG_LEVEL:-INFO}" >&2
echo "Timeout: ${MCP_TIMEOUT:-300}s" >&2
echo "Rate limit: ${MCP_RATE_LIMIT:-5}s between scans" >&2

if [ -n "$MCP_ALLOWED_TARGETS" ]; then
    echo "Allowed targets: $MCP_ALLOWED_TARGETS" >&2
else
    echo "Allowed targets: ALL (not recommended for production)" >&2
fi

echo "Blocked targets: ${MCP_BLOCKED_TARGETS:-localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}" >&2

# Ensure we're in the app directory
cd /app

# Activate virtual environment
source /app/venv/bin/activate

# Execute the MCP server
exec "$@"
