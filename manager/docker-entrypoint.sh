#!/usr/bin/env bash
set -euo pipefail
log(){ echo "[entrypoint] $*"; }

API_SSL_DIR="/var/ossec/api/configuration/ssl"
CRT_SRC="/etc/wazuh/certs/server.pem"
KEY_SRC="/etc/wazuh/certs/server-key.pem"
CRT_DST="$API_SSL_DIR/server.crt"
KEY_DST="$API_SSL_DIR/server.key"

# Ensure API SSL dir exists before copying
mkdir -p "$API_SSL_DIR"

if [[ -f "$CRT_SRC" && -f "$KEY_SRC" ]]; then
  log "Installing API TLS certs..."
  install -o wazuh -g wazuh -m 0644 "$CRT_SRC" "$CRT_DST"
  install -o wazuh -g wazuh -m 0640 "$KEY_SRC" "$KEY_DST"
else
  log "WARN: missing $CRT_SRC or $KEY_SRC (API TLS may fail)"
fi

# Start Wazuh
log "Starting Wazuh..."
/var/ossec/bin/wazuh-control start

# Keep alive & show useful logs
exec tail -F /var/ossec/logs/ossec.log /var/ossec/logs/cluster.log
