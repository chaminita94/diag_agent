#!/usr/bin/env bash
set -euo pipefail
# setup_diag.sh — portable installer/runner
# Runs diag_agent_single.py from the same folder (NO /opt/diag needed)

SERVICE_NAME="diag-agent"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# Directory where this script lives
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIAG_PY="${SCRIPT_DIR}/diag_agent_single.py"
VENV_DIR="${SCRIPT_DIR}/venv"

# Network parameters
BIND_IP="${1:-$(hostname -I | awk '{print $1}' || echo 127.0.0.1)}"
ALLOW_FROM="${2:-${BIND_IP%.*}.0/24}"
PORT="${3:-8080}"

echo "[setup] Installing system dependencies..."
apt-get update -y

# List of APT packages to install (Ubuntu 24.04 compatible)
PKGS=(
    python3
    python3-pip
    python3-venv
    python3-dev
    build-essential
    curl
    jq
    git
    nmap
    ssh-audit
    smbclient
    samba-common-bin
    apt-transport-https
    gnupg
    lsb-release
    ca-certificates
    libpango-1.0-0
    libpangocairo-1.0-0
    libcairo2
)

for pkg in "${PKGS[@]}"; do
    if ! dpkg -l | grep -qw "$pkg"; then
        apt-get install -y --no-install-recommends "$pkg"
    fi
done

echo "[setup] Creating Python virtual environment..."
if [ ! -d "${VENV_DIR}" ]; then
    python3 -m venv "${VENV_DIR}"
fi

echo "[setup] Installing Python dependencies inside venv..."
"${VENV_DIR}/bin/pip" install --no-cache-dir \
    flask \
    psutil \
    weasyprint \
    impacket \
    ldap3 \
    pyyaml \
    pyhanko[crypto] \
    cryptography \
    pyhanko-certvalidator \
    requests \
    urllib3 \
    beautifulsoup4 \
    googlesearch-python \
    google-api-python-client

echo "[setup] Installing enum4linux-ng (GitHub clone)..."
if [ ! -d "${SCRIPT_DIR}/enum4linux-ng" ]; then
    git clone https://github.com/cddmp/enum4linux-ng.git "${SCRIPT_DIR}/enum4linux-ng"
fi

echo "[setup] Checking for branding assets..."
if [ ! -f "${SCRIPT_DIR}/cshield.png" ]; then
    echo "  ⚠️  WARNING: cshield.png not found in ${SCRIPT_DIR}"
    echo "      PDF reports will miss the Cybershield logo."
else
    echo "  ✓ Found cshield.png"
fi
echo "[setup] Setting up PDF signing certificates..."
CERT_DIR="${SCRIPT_DIR}/certs"
mkdir -p "${CERT_DIR}"

if [ ! -f "${CERT_DIR}/cybershield.key" ]; then
    echo "  → Generating private key..."
    openssl genrsa -out "${CERT_DIR}/cybershield.key" 2048
    
    echo "  → Generating self-signed certificate (valid 10 years)..."
    openssl req -new -x509 \
        -key "${CERT_DIR}/cybershield.key" \
        -out "${CERT_DIR}/cybershield.crt" \
        -days 3650 \
        -subj "/C=ES/ST=Barcelona/L=Barcelona/O=Cybershield Solutions/OU=Security Audit Division/CN=Cybershield Solutions/emailAddress=security@cybershield.solutions"
    
    echo "  → Securing private key..."
    chmod 600 "${CERT_DIR}/cybershield.key"
    
    echo "  ✓ Certificate created: ${CERT_DIR}/cybershield.crt"
else
    echo "  ✓ Certificate already exists"
fi

echo "[setup] Creating systemd service..."
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Diag Agent (no-auth) - portable version
After=network.target

[Service]
Type=simple
ExecStart=${VENV_DIR}/bin/python3 ${DIAG_PY} --host ${BIND_IP} --port ${PORT} --allow-from ${ALLOW_FROM}
WorkingDirectory=${SCRIPT_DIR}
Restart=on-failure
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "[setup] Reloading systemd..."
systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.service"

echo "[setup] DONE!"
echo "Service running: systemctl status ${SERVICE_NAME}"
echo "Follow logs:     journalctl -u ${SERVICE_NAME} -f"
echo "Access via:      http://${BIND_IP}:${PORT}/"
echo "enum4linux-ng at: ${SCRIPT_DIR}/enum4linux-ng/enum4linux-ng.py"
echo "Access via:      http://${BIND_IP}:${PORT}/"
echo "enum4linux-ng at: ${SCRIPT_DIR}/enum4linux-ng/enum4linux-ng.py"