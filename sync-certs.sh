#!/usr/bin/env bash
set -euo pipefail

# ==== Detect the real user when running with sudo ====
OWNER_USER="${SUDO_USER:-$USER}"
OWNER_UID="$(id -u "$OWNER_USER")"
OWNER_GID="$(id -g "$OWNER_USER")"

# Resolve the real user's HOME
if HOME_USER="$(getent passwd "$OWNER_USER" | cut -d: -f6)"; then :; else
  HOME_USER="$(eval echo "~$OWNER_USER")"
fi

# ==== Default paths (overridable via env) ====
SRC_DIR="${SRC_DIR:-$HOME_USER/Wazuh/wazuh-certs/wazuh-certificates}"
DEST_DIR="${DEST_DIR:-$HOME_USER/Wazuh/full-stack/wazuh-docker/certs}"
# Which existing cert to reuse as Filebeat client cert (only for lab)
FILEBEAT_SRC_BASENAME="${FILEBEAT_SRC_BASENAME:-wazuh-manager-1}"

echo "[i] Target user: $OWNER_USER (uid=$OWNER_UID gid=$OWNER_GID)"
echo "[i] Source:  $SRC_DIR"
echo "[i] Dest:    $DEST_DIR"

# Helper: copy with mode, fail if source is missing
copy() {
  local src="$1" dst="$2" mode="$3"
  [[ -f "$src" ]] || { echo "ERROR: missing $src"; exit 1; }
  install -m "$mode" -D "$src" "$dst"
}

# Ensure destination structure exists
mkdir -p \
  "$DEST_DIR/indexer" \
  "$DEST_DIR/dashboard" \
  "$DEST_DIR/manager-1" \
  "$DEST_DIR/manager-2" \
  "$DEST_DIR/filebeat"

# --- Indexer ---
echo "[i] Indexer"
copy "$SRC_DIR/wazuh-indexer.pem"     "$DEST_DIR/indexer/indexer.pem"     0644
copy "$SRC_DIR/wazuh-indexer-key.pem" "$DEST_DIR/indexer/indexer-key.pem" 0640
copy "$SRC_DIR/admin.pem"             "$DEST_DIR/indexer/admin.pem"       0644
copy "$SRC_DIR/admin-key.pem"         "$DEST_DIR/indexer/admin-key.pem"   0640
copy "$SRC_DIR/root-ca.pem"           "$DEST_DIR/indexer/root-ca.pem"     0644

# --- Managers ---
echo "[i] Manager 1"
copy "$SRC_DIR/wazuh-manager-1.pem"     "$DEST_DIR/manager-1/server.pem"     0644
copy "$SRC_DIR/wazuh-manager-1-key.pem" "$DEST_DIR/manager-1/server-key.pem" 0640
copy "$SRC_DIR/root-ca.pem"             "$DEST_DIR/manager-1/root-ca.pem"    0644

echo "[i] Manager 2"
copy "$SRC_DIR/wazuh-manager-2.pem"     "$DEST_DIR/manager-2/server.pem"     0644
copy "$SRC_DIR/wazuh-manager-2-key.pem" "$DEST_DIR/manager-2/server-key.pem" 0640
copy "$SRC_DIR/root-ca.pem"             "$DEST_DIR/manager-2/root-ca.pem"    0644

# --- Dashboard ---
echo "[i] Dashboard"
copy "$SRC_DIR/wazuh-dashboard.pem"     "$DEST_DIR/dashboard/dashboard.pem"     0644
copy "$SRC_DIR/wazuh-dashboard-key.pem" "$DEST_DIR/dashboard/dashboard-key.pem" 0640
copy "$SRC_DIR/root-ca.pem"             "$DEST_DIR/dashboard/root-ca.pem"       0644

# --- Filebeat (reuse an existing server cert as client cert for lab) ---
echo "[i] Filebeat"
if [[ -f "$SRC_DIR/filebeat.pem" && -f "$SRC_DIR/filebeat-key.pem" ]]; then
  copy "$SRC_DIR/filebeat.pem"      "$DEST_DIR/filebeat/filebeat.pem"      0644
  copy "$SRC_DIR/filebeat-key.pem"  "$DEST_DIR/filebeat/filebeat-key.pem"  0640
else
  copy "$SRC_DIR/${FILEBEAT_SRC_BASENAME}.pem"     "$DEST_DIR/filebeat/filebeat.pem"      0644
  copy "$SRC_DIR/${FILEBEAT_SRC_BASENAME}-key.pem" "$DEST_DIR/filebeat/filebeat-key.pem"  0640
fi
copy "$SRC_DIR/root-ca.pem" "$DEST_DIR/filebeat/root-ca.pem" 0644

# Ownership: if running as root, set ownership back to the real user
if [[ $EUID -eq 0 ]]; then
  chown -R "$OWNER_UID:$OWNER_GID" "$DEST_DIR"
fi

echo "[✓] Certificates copied. Keys 0640, certs/CA 0644."
echo "SANs quick check:"
echo "  openssl x509 -in \"$DEST_DIR/manager-1/server.pem\" -noout -text | sed -n '/Subject Alternative Name/,+2p'"
