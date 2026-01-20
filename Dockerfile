# Diag Agent - Docker Tactical Edition (2026)
# Optimization for TRUE OFFLINE USB-based security audits

FROM ubuntu:24.04

# Avoid prompts during installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TRIVY_CACHE_DIR=/app/trivy_cache

# 1. Install System Dependencies & Official Repos
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ca-certificates \
    gnupg \
    lsb-release \
    curl \
    jq \
    git \
    nmap \
    ssh-audit \
    smbclient \
    samba-common-bin \
    apt-transport-https \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libpcap-dev \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# 2. Install Trivy from Official Repository
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y trivy \
    && rm -rf /var/lib/apt/lists/*

# 3. Set up Working Directory
WORKDIR /app

# 4. Copy Application Code
COPY "Diag agent/diag_agent_single.py" .
COPY "Diag agent/pentest_agent.py" .
COPY "Diag agent/diagbot.py" .
COPY "cshield.png" .

# 5. Install Python Dependencies
RUN pip install --no-cache-dir --break-system-packages \
    flask==3.0.* \
    psutil==5.9.* \
    weasyprint==61.* \
    impacket==0.11.* \
    ldap3==2.9.* \
    pyyaml==6.0.* \
    pyhanko[crypto]==0.21.* \
    cryptography \
    pyhanko-certvalidator \
    requests \
    urllib3 \
    beautifulsoup4 \
    googlesearch-python \
    google-api-python-client \
    scapy \
    shodan

# 6. Pre-clone Recon Tools & Initialize Databases
RUN git clone https://github.com/cddmp/enum4linux-ng.git /app/enum4linux-ng
RUN git clone https://github.com/laramies/theHarvester.git /app/theHarvester && \
    pip install --no-cache-dir --break-system-packages -r /app/theHarvester/requirements/base.txt

# IMPORTANT FOR OFFLINE: Pre-download Trivy database
# We create the directory first and then download the DB
RUN mkdir -p $TRIVY_CACHE_DIR \
    && trivy fs --download-db-only --scanners vuln /

# 7. Set up theHarvester API keys directory
RUN mkdir -p /root/.theHarvester

# 8. Expose default port
EXPOSE 8080

# 9. Start the Agent
ENTRYPOINT ["python3", "diag_agent_single.py", "--host", "0.0.0.0", "--port", "8080"]
