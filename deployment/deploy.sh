#!/usr/bin/env bash

set -euo pipefail   # Exit on any error, treat unset vars as errors, fail on pipe errors
IFS=$'\n\t'         # Safer word splitting

# -----------------------------------------------------------------------
# Colours — makes output easier to scan in a terminal
# -----------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

log()     { echo -e "${CYAN}[DEPLOY]${RESET} $*"; }
success() { echo -e "${GREEN}[  OK  ]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[ WARN ]${RESET} $*"; }
die()     { echo -e "${RED}[ FAIL ]${RESET} $*" >&2; exit 1; }

# -----------------------------------------------------------------------
# Must run as root (needed for apt, docker, iptables)
# -----------------------------------------------------------------------
[[ "$EUID" -eq 0 ]] || die "Please run as root: sudo bash deployment/deploy.sh"

# -----------------------------------------------------------------------
# 0. Banner
# -----------------------------------------------------------------------
echo ""
echo -e "${BOLD}${CYAN}=================================================${RESET}"
echo -e "${BOLD}${CYAN}  HNG Anomaly Detection Engine — Deployment     ${RESET}"
echo -e "${BOLD}${CYAN}=================================================${RESET}"
echo ""

# -----------------------------------------------------------------------
# 1. Collect configuration from the operator
#    We prompt interactively so no secrets ever touch a config file
#    before the operator has a chance to review.
# -----------------------------------------------------------------------
log "Collecting configuration..."
echo ""

# Detect the server's public IP automatically, let operator confirm/override
DETECTED_IP=$(curl -fsSL https://api.ipify.org 2>/dev/null || echo "")

read -rp "  Server public IP [${DETECTED_IP}]: " SERVER_IP
SERVER_IP="${SERVER_IP:-$DETECTED_IP}"
[[ -n "$SERVER_IP" ]] || die "Server IP is required."

read -rp "  Dashboard domain/subdomain (e.g. monitor.example.com) [${SERVER_IP}]: " DASHBOARD_DOMAIN
DASHBOARD_DOMAIN="${DASHBOARD_DOMAIN:-$SERVER_IP}"

read -rp "  Slack webhook URL (leave blank to skip alerts): " SLACK_WEBHOOK_URL
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"

read -rp "  Nextcloud admin username [admin]: " NC_ADMIN_USER
NC_ADMIN_USER="${NC_ADMIN_USER:-admin}"

# Generate a random password if operator doesn't supply one
DEFAULT_NC_PASS=$(tr -dc 'A-Za-z0-9!@#' </dev/urandom | head -c 20 || true)
read -rsp "  Nextcloud admin password [auto-generated, press Enter]: " NC_ADMIN_PASS
echo ""
NC_ADMIN_PASS="${NC_ADMIN_PASS:-$DEFAULT_NC_PASS}"

DEFAULT_DB_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24 || true)
DEFAULT_ROOT_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24 || true)
# These are always auto-generated — no need to bother the operator
NC_DB_PASS="$DEFAULT_DB_PASS"
MYSQL_ROOT_PASS="$DEFAULT_ROOT_PASS"

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

echo ""
log "Configuration summary:"
echo "  Server IP:         ${SERVER_IP}"
echo "  Dashboard domain:  ${DASHBOARD_DOMAIN}"
echo "  Nextcloud admin:   ${NC_ADMIN_USER}"
echo "  Slack alerts:      ${SLACK_WEBHOOK_URL:-(disabled)}"
echo "  Repo directory:    ${REPO_DIR}"
echo ""
read -rp "  Proceed? [Y/n]: " CONFIRM
CONFIRM="${CONFIRM:-Y}"
[[ "$CONFIRM" =~ ^[Yy]$ ]] || die "Deployment cancelled."

# -----------------------------------------------------------------------
# 2. System packages — Docker, Docker Compose plugin, iptables
# -----------------------------------------------------------------------
echo ""
log "Step 1/7 — Installing system packages..."

apt-get update -qq
apt-get install -y -qq \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    iptables \
    iptables-persistent \
    git \
    2>/dev/null

# Install Docker if not already present
if ! command -v docker &>/dev/null; then
    log "Docker not found — installing..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
      > /etc/apt/sources.list.d/docker.list

    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
    success "Docker installed."
else
    success "Docker already installed ($(docker --version | cut -d' ' -f3 | tr -d ','))."
fi

# -----------------------------------------------------------------------
# 3. Create required directories on the host
# -----------------------------------------------------------------------
echo ""
log "Step 2/7 — Creating host directories..."

mkdir -p /var/log/detector
chmod 777 /var/log/detector   # Detector container writes here as non-root

success "Directories ready."

# -----------------------------------------------------------------------
# 4. Write the .env file from the collected values
#    This file is the single source of truth for all secrets at runtime.
# -----------------------------------------------------------------------
echo ""
log "Step 3/7 — Writing .env file..."

cat > "${REPO_DIR}/.env" <<EOF
# Generated by deploy.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Do not commit this file to git.

SERVER_IP=${SERVER_IP}
SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL}
NEXTCLOUD_ADMIN_USER=${NC_ADMIN_USER}
NEXTCLOUD_ADMIN_PASSWORD=${NC_ADMIN_PASS}
NEXTCLOUD_DB_PASSWORD=${NC_DB_PASS}
MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASS}
EOF

chmod 600 "${REPO_DIR}/.env"   # Only root can read it
success ".env written to ${REPO_DIR}/.env"

# -----------------------------------------------------------------------
# 5. Configure Nginx on the HOST to reverse-proxy the dashboard
#    so it's reachable at the dashboard domain on port 80
#    (the detector's Flask server runs on 127.0.0.1:8080)
# -----------------------------------------------------------------------
echo ""
log "Step 4/7 — Configuring host Nginx for dashboard reverse proxy..."

if ! command -v nginx &>/dev/null; then
    apt-get install -y -qq nginx
fi

# Write the dashboard vhost — proxies the public domain to the detector's port
cat > /etc/nginx/sites-available/hng-dashboard <<NGINXEOF
server {
    listen 80;
    server_name ${DASHBOARD_DOMAIN};

    # Proxy to Flask dashboard running in the detector container (host network)
    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_read_timeout 10s;

        # Allow the live dashboard to auto-refresh without keep-alive issues
        proxy_http_version 1.1;
        proxy_set_header   Connection "";
    }
}
NGINXEOF

# Enable the site and disable the default placeholder
ln -sf /etc/nginx/sites-available/hng-dashboard /etc/nginx/sites-enabled/hng-dashboard
rm -f /etc/nginx/sites-enabled/default

nginx -t && systemctl reload nginx
success "Host Nginx configured for dashboard at http://${DASHBOARD_DOMAIN}"

# -----------------------------------------------------------------------
# 6. Pull images and start the Docker Compose stack
# -----------------------------------------------------------------------
echo ""
log "Step 5/7 — Pulling Docker images (this may take a few minutes)..."

cd "${REPO_DIR}"
docker compose pull --quiet
success "Images pulled."

log "Step 6/7 — Building detector image..."
docker compose build --quiet detector
success "Detector image built."

log "Starting all services..."
docker compose up -d

# -----------------------------------------------------------------------
# 7. Health checks — wait for each service to become ready
# -----------------------------------------------------------------------
echo ""
log "Step 7/7 — Running health checks..."

# Helper: retry a command up to N times with a delay
wait_for() {
    local label="$1"
    local cmd="$2"
    local retries="${3:-15}"
    local delay="${4:-5}"
    local i=0
    while ! eval "$cmd" &>/dev/null; do
        i=$((i+1))
        [[ $i -ge $retries ]] && die "${label} did not become healthy after $((retries * delay))s."
        echo -n "."
        sleep "$delay"
    done
    echo ""
    success "${label} is healthy."
}

# Nginx inside Docker should respond to the health endpoint
echo -n "  Waiting for Nginx"
wait_for "Nginx" "curl -fsSL --max-time 3 http://localhost/nginx-health"

# Detector Flask dashboard health endpoint
echo -n "  Waiting for Detector dashboard"
wait_for "Detector dashboard" "curl -fsSL --max-time 3 http://localhost:8080/health"

# Persist iptables rules across reboots so bans survive a restart
echo ""
log "Persisting iptables rules..."
netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 || true

# -----------------------------------------------------------------------
# 8. Print the final summary
# -----------------------------------------------------------------------
echo ""
echo -e "${BOLD}${GREEN}=================================================${RESET}"
echo -e "${BOLD}${GREEN}  Deployment Complete!                           ${RESET}"
echo -e "${BOLD}${GREEN}=================================================${RESET}"
echo ""
echo -e "  ${BOLD}Nextcloud (IP only):${RESET}    http://${SERVER_IP}"
echo -e "  ${BOLD}Metrics dashboard:${RESET}      http://${DASHBOARD_DOMAIN}"
echo -e "  ${BOLD}Nextcloud admin user:${RESET}   ${NC_ADMIN_USER}"
echo -e "  ${BOLD}Nextcloud admin pass:${RESET}   ${NC_ADMIN_PASS}"
echo ""
echo -e "  ${BOLD}Useful commands:${RESET}"
echo "    docker compose logs -f detector     # Watch detector output live"
echo "    docker compose ps                   # Check container status"
echo "    sudo iptables -L INPUT -n           # View active bans"
echo "    tail -f /var/log/detector/audit.log # Watch the audit log"
echo ""
echo -e "  ${YELLOW}Save your Nextcloud password — it won't be shown again.${RESET}"
echo ""
