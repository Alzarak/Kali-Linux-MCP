# Kali Linux MCP Server
# Exposes security testing tools via Model Context Protocol
#
# WARNING: For authorized security testing only.
# Only use against systems you own or have explicit permission to test.

FROM kalilinux/kali-rolling

LABEL maintainer="security-mcp"
LABEL description="MCP Server for Kali Linux Security Tools"
LABEL version="1.0.0"

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Set locale
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Update and install base dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    curl \
    wget \
    git \
    unzip \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install security tools - curated selection for defensive testing
# Each tool is commonly used in legitimate penetration testing
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Network scanning and enumeration
    nmap \
    # Web vulnerability scanning
    nikto \
    # SQL injection testing
    sqlmap \
    # Web fuzzing / directory discovery
    ffuf \
    gobuster \
    # SSL/TLS analysis
    testssl.sh \
    # DNS tools
    dnsrecon \
    # HTTP tools
    httpie \
    curl \
    # Wordlists for fuzzing
    wordlists \
    seclists \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei (template-based vulnerability scanner)
# Installed separately as it's not in default Kali repos or needs latest version
RUN curl -sSfL https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei

# Update Nuclei templates
RUN nuclei -update-templates -silent || true

# Create non-root user for running tools
RUN useradd -m -s /bin/bash -u 1000 mcpuser \
    && mkdir -p /app /home/mcpuser/.local \
    && chown -R mcpuser:mcpuser /app /home/mcpuser

# Set up Python virtual environment
WORKDIR /app
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ /app/src/
COPY entrypoint.sh /app/

# Set permissions
RUN chmod +x /app/entrypoint.sh \
    && chown -R mcpuser:mcpuser /app

# Some tools need to run with elevated privileges for certain operations
# We'll handle this by selectively running specific tools as root when needed
# but the MCP server process itself runs as mcpuser

# Environment variables with secure defaults
ENV MCP_ALLOWED_TARGETS=""
ENV MCP_BLOCKED_TARGETS="localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,224.0.0.0/4"
ENV MCP_TIMEOUT="300"
ENV MCP_RATE_LIMIT="5"
ENV MCP_LOG_LEVEL="INFO"

# Tools that require root access (like SYN scans) won't work in rootless mode
# This is a security tradeoff - we can run basic scans without root
USER mcpuser

# Expose nothing - MCP uses stdio transport
# EXPOSE - intentionally not used

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "-m", "src.server"]
