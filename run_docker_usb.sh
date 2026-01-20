#!/bin/bash
# Diag Agent - USB Tactical Launcher (v2026)
# Professional Plug & Play auditor tool

# 1. Default Configuration
IMAGE_NAME="diag-agent:tactical"
IMAGE_FILE="diag_agent_v2026.tar"
CONTAINER_NAME="diag_agent_live"
PORT=8080

# Get absolute path of the USB directory
USB_PATH="$(cd "$(dirname "$0")" && pwd)"
REPORTS_DIR="${USB_PATH}/reports"
CERTS_DIR="${USB_PATH}/certs"
CACHE_DIR="${USB_PATH}/trivy_cache"
LOGS_DIR="/var/log"

# Parse arguments
FULL_MODE=false
HOST_NET=false
RESTART_POLICY="no"
USE_RM="--rm"

show_help() {
    echo "Usage: sudo ./run_docker_usb.sh [options]"
    echo ""
    echo "Options:"
    echo "  --full      Enable Full Visibility (privileged, pid=host, var/log mount)"
    echo "  --hostnet   Enable Host Network mode (bypass container network isolation)"
    echo "  --restart   Enable 'unless-stopped' restart policy (container won't be deleted on exit)"
    echo "  --help      Show this help message"
    echo ""
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --full) FULL_MODE=true ;;
        --hostnet) HOST_NET=true ;;
        --restart) RESTART_POLICY="unless-stopped"; USE_RM="" ;;
        --help) show_help; exit 0 ;;
        *) echo "Unknown parameter: $1"; show_help; exit 1 ;;
    esac
    shift
done

echo "--------------------------------------------------------"
echo "🛡️  Cybershield Solutions - Tactical Deployment"
echo "--------------------------------------------------------"

# 2. Safety Checks
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Error: Please run as root (sudo ./run_docker_usb.sh)"
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "❌ Error: Docker is not installed on this host."
    exit 1
fi

if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null ; then
    echo "❌ Error: Port $PORT is already in use by another process."
    exit 1
fi

# 3. Directory Creation
mkdir -p "${REPORTS_DIR}" "${CERTS_DIR}" "${CACHE_DIR}"

# 4. Load Docker image (Offline Mode)
if [[ "$(docker images -q ${IMAGE_NAME} 2> /dev/null)" == "" ]]; then
    if [ -f "${USB_PATH}/images/${IMAGE_FILE}" ]; then
        echo "[+] Loading Docker image from USB (this may take a moment)..."
        docker load -i "${USB_PATH}/images/${IMAGE_FILE}"
    else
        echo "❌ Error: Image file ${IMAGE_FILE} not found and image ${IMAGE_NAME} not in cache."
        exit 1
    fi
fi

# 5. Clean up existing containers
if [ "$(docker ps -aq -f name=${CONTAINER_NAME})" ]; then
    echo "[+] Removing existing container..."
    docker rm -f ${CONTAINER_NAME} >/dev/null
fi

# 6. Build the Docker Command
DOCKER_CMD="docker run -d $USE_RM --name ${CONTAINER_NAME} --restart=${RESTART_POLICY}"

# Mounts
DOCKER_CMD+=" -v ${REPORTS_DIR}:/app/reports"
DOCKER_CMD+=" -v ${CERTS_DIR}:/app/certs"
DOCKER_CMD+=" -v ${CACHE_DIR}:/app/trivy_cache"

# Optional Flags
if [ "$FULL_MODE" = true ]; then
    echo "[!] VISIBILITY: Full Mode Enabled (Privileged + Host PID + Log Mount)"
    DOCKER_CMD+=" --privileged --pid=host -v ${LOGS_DIR}:/var/log:ro"
else
    echo "[i] VISIBILITY: Safe Mode (Isolated)"
fi

if [ "$HOST_NET" = true ]; then
    echo "[!] NETWORK: Host Mode Enabled"
    DOCKER_CMD+=" --net=host"
else
    echo "[i] NETWORK: Bridge Mode (Port ${PORT} mapped)"
    DOCKER_CMD+=" -p ${PORT}:${PORT}"
fi

# 7. Run Application
echo "[+] Starting Diag Agent..."
eval $DOCKER_CMD "${IMAGE_NAME}"

# 8. Verification & Final Info
IP_ADDR=$(hostname -I | awk '{print $1}')
echo "--------------------------------------------------------"
echo "✅ DEPLOYMENT SUCCESSFUL"
echo "Access the Dashboard at: http://${IP_ADDR}:${PORT}/"
echo "USB Persistence active for: /reports, /certs, /trivy_cache"
echo "--------------------------------------------------------"
echo "To view live logs: docker logs -f ${CONTAINER_NAME}"
echo "To stop the agent: docker stop ${CONTAINER_NAME}"
