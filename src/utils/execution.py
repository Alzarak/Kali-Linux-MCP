"""
Command Execution Module

Provides safe command execution with timeouts, output capturing,
and proper subprocess management.

WARNING: All commands should be constructed as argument lists,
never using shell=True or string formatting with user input.
"""

import asyncio
import logging
import os
import shutil
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Default timeout in seconds
DEFAULT_TIMEOUT = int(os.environ.get("MCP_TIMEOUT", "300"))

# Maximum output size (characters)
MAX_OUTPUT_SIZE = 100_000


@dataclass
class CommandResult:
    """Result of a command execution."""

    stdout: str
    stderr: str
    return_code: int
    timed_out: bool = False

    @property
    def success(self) -> bool:
        """Check if the command succeeded."""
        return self.return_code == 0 and not self.timed_out

    @property
    def output(self) -> str:
        """Get combined output (stdout + stderr if error)."""
        if self.success:
            return self.stdout
        return f"{self.stdout}\n{self.stderr}".strip()


def check_tool_available(tool: str) -> bool:
    """Check if a command-line tool is available."""
    return shutil.which(tool) is not None


async def run_command(
    cmd: list[str],
    timeout: Optional[int] = None,
    cwd: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
) -> CommandResult:
    """
    Execute a command asynchronously with timeout and output capture.

    Args:
        cmd: Command and arguments as a list (NO SHELL INTERPRETATION)
        timeout: Timeout in seconds (uses MCP_TIMEOUT env var if not specified)
        cwd: Working directory for the command
        env: Additional environment variables

    Returns:
        CommandResult with stdout, stderr, and return code

    Raises:
        TimeoutError: If the command exceeds the timeout
        ValueError: If the command list is empty
        FileNotFoundError: If the command executable is not found
    """
    if not cmd:
        raise ValueError("Command list cannot be empty")

    # Use default timeout if not specified
    if timeout is None:
        timeout = DEFAULT_TIMEOUT

    # Verify the command exists
    executable = cmd[0]
    if not check_tool_available(executable):
        raise FileNotFoundError(f"Command not found: {executable}")

    # Build environment
    process_env = os.environ.copy()
    if env:
        process_env.update(env)

    logger.debug(f"Executing command: {' '.join(cmd)}")
    logger.debug(f"Timeout: {timeout}s")

    try:
        # Create the subprocess - NO SHELL
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=process_env,
        )

        try:
            # Wait for completion with timeout
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )

            # Decode output
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")

            # Truncate if too long
            if len(stdout) > MAX_OUTPUT_SIZE:
                stdout = stdout[:MAX_OUTPUT_SIZE] + "\n... [OUTPUT TRUNCATED]"
            if len(stderr) > MAX_OUTPUT_SIZE:
                stderr = stderr[:MAX_OUTPUT_SIZE] + "\n... [OUTPUT TRUNCATED]"

            result = CommandResult(
                stdout=stdout.strip(),
                stderr=stderr.strip(),
                return_code=process.returncode or 0,
            )

            logger.debug(f"Command completed with return code: {result.return_code}")
            return result

        except asyncio.TimeoutError:
            # Kill the process on timeout
            logger.warning(f"Command timed out after {timeout}s, killing process")
            process.kill()
            await process.wait()

            raise TimeoutError(f"Command timed out after {timeout} seconds")

    except FileNotFoundError:
        raise
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        raise


async def run_command_with_streaming(
    cmd: list[str],
    timeout: Optional[int] = None,
    line_callback: Optional[callable] = None,
) -> CommandResult:
    """
    Execute a command with real-time output streaming.

    This is useful for long-running commands where progress updates are helpful.

    Args:
        cmd: Command and arguments as a list
        timeout: Timeout in seconds
        line_callback: Async function called for each output line

    Returns:
        CommandResult with full output
    """
    if timeout is None:
        timeout = DEFAULT_TIMEOUT

    executable = cmd[0]
    if not check_tool_available(executable):
        raise FileNotFoundError(f"Command not found: {executable}")

    logger.debug(f"Executing (streaming): {' '.join(cmd)}")

    stdout_lines: list[str] = []
    stderr_lines: list[str] = []

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    async def read_stream(stream, lines: list[str], is_stderr: bool = False):
        """Read lines from a stream."""
        while True:
            try:
                line = await asyncio.wait_for(stream.readline(), timeout=1.0)
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip()
                lines.append(decoded)
                if line_callback:
                    await line_callback(decoded, is_stderr)
            except asyncio.TimeoutError:
                # Check if process is still running
                if process.returncode is not None:
                    break
                continue

    try:
        # Read both streams concurrently with overall timeout
        await asyncio.wait_for(
            asyncio.gather(
                read_stream(process.stdout, stdout_lines),
                read_stream(process.stderr, stderr_lines, True),
            ),
            timeout=timeout,
        )

        await process.wait()

        stdout = "\n".join(stdout_lines)
        stderr = "\n".join(stderr_lines)

        # Truncate if needed
        if len(stdout) > MAX_OUTPUT_SIZE:
            stdout = stdout[:MAX_OUTPUT_SIZE] + "\n... [OUTPUT TRUNCATED]"
        if len(stderr) > MAX_OUTPUT_SIZE:
            stderr = stderr[:MAX_OUTPUT_SIZE] + "\n... [OUTPUT TRUNCATED]"

        return CommandResult(
            stdout=stdout,
            stderr=stderr,
            return_code=process.returncode or 0,
        )

    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        raise TimeoutError(f"Command timed out after {timeout} seconds")


def format_command_output(result: CommandResult, tool_name: str) -> str:
    """
    Format command output for MCP response.

    Args:
        result: The CommandResult to format
        tool_name: Name of the tool that was executed

    Returns:
        Formatted string for the MCP response
    """
    output_parts = []

    if result.timed_out:
        output_parts.append(f"⚠️ {tool_name} timed out")
    elif not result.success:
        output_parts.append(f"⚠️ {tool_name} completed with warnings (exit code: {result.return_code})")
    else:
        output_parts.append(f"✓ {tool_name} completed successfully")

    output_parts.append("")
    output_parts.append("=" * 60)
    output_parts.append("")

    if result.stdout:
        output_parts.append(result.stdout)

    if result.stderr and not result.success:
        output_parts.append("")
        output_parts.append("--- Errors/Warnings ---")
        output_parts.append(result.stderr)

    return "\n".join(output_parts)
