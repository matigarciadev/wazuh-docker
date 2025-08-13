# ──────────────────────────────────────────────────────────
# Wazuh Agent 4.12 – CentOS Stream 9
# ──────────────────────────────────────────────────────────
FROM quay.io/centos/centos:stream9

ENV WAZUH_VERSION=4.12.0 \
    MANAGER_HOST=wazuh-manager \
    MANAGER_PORT=1515 \
    AGENT_NAME=""

# 1. Dependencies + Wazuh repository
RUN dnf -y update && \
    dnf -y swap curl-minimal curl && \
    dnf -y install gnupg2 procps-ng hostname shadow-utils && \
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH && \
    printf "[wazuh]\nname=Wazuh Repository\nbaseurl=https://packages.wazuh.com/4.x/yum/\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\n" \
        > /etc/yum.repos.d/wazuh.repo && \
    dnf -y install "wazuh-agent-${WAZUH_VERSION}-*" || dnf -y install wazuh-agent && \
    dnf clean all

# 2. Entry point: self-registration and foreground start
RUN cat <<'EOF' > /usr/local/bin/entrypoint.sh
#!/usr/bin/env bash
set -e
MANAGER_HOST=${MANAGER_HOST:-wazuh-manager}
MANAGER_PORT=${MANAGER_PORT:-1515}
AGENT_NAME=${AGENT_NAME:-$(hostname)}

# ---------- FIM (Syscheck) knobs ----------
# Override via environment variables in docker-compose
FIM_REALTIME=${FIM_REALTIME:-yes}   # yes|1 to enable realtime
FIM_DIRS=${FIM_DIRS:-/etc}          # comma- or space-separated list of dirs
FIM_FREQUENCY=${FIM_FREQUENCY:-}    # e.g., 600 for tests; empty = leave as-is

conf="/var/ossec/etc/ossec.conf"

echo "[entrypoint] Waiting for DNS of ${MANAGER_HOST}..."
for i in {1..30}; do
  if getent hosts "$MANAGER_HOST" >/dev/null; then break; fi
  sleep 2
done

echo "[entrypoint] Setting <address> to ${MANAGER_HOST}..."
sed -i "0,/<address>/{s|<address>.*</address>|<address>${MANAGER_HOST}</address>|}" "$conf"

# Auto-enroll if client.keys is missing/empty
if [ ! -s /var/ossec/etc/client.keys ]; then
  echo "[entrypoint] Registering agent to ${MANAGER_HOST}:${MANAGER_PORT}..."
  /var/ossec/bin/agent-auth -m "$MANAGER_HOST" -p "$MANAGER_PORT" -A "$AGENT_NAME" || true
fi

echo "[entrypoint] Starting Wazuh agent..."
/var/ossec/bin/wazuh-control start

echo "[entrypoint] Tailing logs..."
exec tail -F /var/ossec/logs/ossec.log /var/ossec/logs/active-responses.log
EOF
RUN chmod +x /usr/local/bin/entrypoint.sh

# only needed for active syslog
EXPOSE 1514/udp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
