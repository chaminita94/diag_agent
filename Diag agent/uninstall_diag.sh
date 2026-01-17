#!/usr/bin/env bash
set -euo pipefail
# uninstall_diag.sh — Complete uninstaller for Diag Agent
# Removes all code, dependencies, and system configurations
# WARNING: This will remove ALL components installed by setup_diag.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SERVICE_NAME="diag-agent"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# Directory where this script lives (same as Diag Agent installation)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/venv"
ENUM4LINUX_DIR="${SCRIPT_DIR}/enum4linux-ng"
CERTS_DIR="${SCRIPT_DIR}/certs"

echo -e "${RED}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║              DIAG AGENT - COMPLETE UNINSTALLER                 ║"
echo "╠════════════════════════════════════════════════════════════════╣"
echo "║  ⚠️  WARNING: This will remove ALL Diag Agent components        ║"
echo "║                                                                 ║"
echo "║  Components to be removed:                                      ║"
echo "║   • Systemd service (diag-agent.service)                       ║"
echo "║   • Python virtual environment (venv/)                          ║"
echo "║   • enum4linux-ng                                               ║"
echo "║   • Digital certificates (certs/)                               ║"
echo "║   • Optional APT packages                                       ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

read -p "Are you sure you want to continue? (type 'YES' to confirm): " CONFIRM
if [ "$CONFIRM" != "YES" ]; then
    echo -e "${YELLOW}Operation cancelled.${NC}"
    exit 0
fi

echo ""
echo -e "${YELLOW}[1/6] Stopping and removing systemd service...${NC}"
if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
    systemctl stop "${SERVICE_NAME}"
    echo "  ✓ Service stopped"
fi

if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
    systemctl disable "${SERVICE_NAME}"
    echo "  ✓ Service disabled"
fi

if [ -f "${SERVICE_FILE}" ]; then
    rm -f "${SERVICE_FILE}"
    systemctl daemon-reload
    echo "  ✓ Service file removed"
else
    echo "  ⓘ Service not found (already removed or never installed)"
fi

echo ""
echo -e "${YELLOW}[2/6] Removing Python virtual environment...${NC}"
if [ -d "${VENV_DIR}" ]; then
    rm -rf "${VENV_DIR}"
    echo "  ✓ venv/ removed"
else
    echo "  ⓘ venv/ not found"
fi

echo ""
echo -e "${YELLOW}[3/6] Removing enum4linux-ng...${NC}"
if [ -d "${ENUM4LINUX_DIR}" ]; then
    rm -rf "${ENUM4LINUX_DIR}"
    echo "  ✓ enum4linux-ng/ removed"
else
    echo "  ⓘ enum4linux-ng/ not found"
fi

echo ""
echo -e "${YELLOW}[4/6] Removing digital certificates...${NC}"
if [ -d "${CERTS_DIR}" ]; then
    rm -rf "${CERTS_DIR}"
    echo "  ✓ certs/ removed"
else
    echo "  ⓘ certs/ not found"
fi

echo ""
echo -e "${YELLOW}[5/6] Remove optional APT packages?${NC}"
echo "  The following packages were installed during setup:"
echo "  nmap, ssh-audit, smbclient, samba-common-bin"
echo ""
read -p "  Do you want to remove these packages? (y/n): " REMOVE_APT

if [ "$REMOVE_APT" = "y" ] || [ "$REMOVE_APT" = "Y" ]; then
    # Only remove security-specific tools, NOT build-essential or common libs
    APT_PKGS_TO_REMOVE=(
        ssh-audit
    )
    
    for pkg in "${APT_PKGS_TO_REMOVE[@]}"; do
        if dpkg -l | grep -qw "$pkg"; then
            apt-get remove -y "$pkg"
            echo "  ✓ $pkg removed"
        fi
    done
    
    # Clean up
    apt-get autoremove -y
    echo "  ✓ Unused dependencies removed"
else
    echo "  ⓘ APT packages preserved"
fi

echo ""
echo -e "${YELLOW}[6/6] Remove Diag Agent Python files?${NC}"
echo "  Main Python files:"
echo "    - diag_agent_single.py"
echo "    - pentest_agent.py"
echo "    - diagbot.py"
echo "    - setup_diag.sh"
echo "    - uninstall_diag.sh (this script)"
echo ""
read -p "  Do you want to remove the Python files as well? (y/n): " REMOVE_PY

if [ "$REMOVE_PY" = "y" ] || [ "$REMOVE_PY" = "Y" ]; then
    rm -f "${SCRIPT_DIR}/diag_agent_single.py"
    rm -f "${SCRIPT_DIR}/pentest_agent.py"
    rm -f "${SCRIPT_DIR}/diagbot.py"
    rm -f "${SCRIPT_DIR}/setup_diag.sh"
    rm -f "${SCRIPT_DIR}/cshield.png"
    rm -f "${SCRIPT_DIR}/verify_pentest_logic.py"
    rm -f "${SCRIPT_DIR}/README.md"
    echo "  ✓ Python files removed"
    
    # Self-destruct
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗"
    echo "║                    UNINSTALLATION COMPLETE                      ║"
    echo "║                                                                   ║"
    echo "║  Diag Agent has been completely removed from the system.        ║"
    echo "║  Thank you for using Cybershield Solutions!                     ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Remove this script last
    rm -f "$0"
else
    echo "  ⓘ Python files preserved"
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗"
    echo "║                    PARTIAL UNINSTALLATION                        ║"
    echo "║                                                                   ║"
    echo "║  System components removed. Python files preserved.             ║"
    echo "║  To remove them manually: rm *.py setup_diag.sh                 ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
fi
