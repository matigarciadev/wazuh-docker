# Wazuh Full Stack Example with Docker

> Scope:
> 1) Clone the stable branch of Wazuh, compile it, and install Wazuh Manager on CentOS (Docker).
> 2) Add two agents to the manager: one CentOS and one Ubuntu.
> 3) Explain what RIDs (counters) are in Wazuh and how to enable/verify them.
> 4) Add a file to enable real-time File Integrity Monitoring (FIM) and show where the alert appears.
> 5) Enroll a third agent using agent enrollment; identify the default agent ID assigned by Authd.
> 6) State how often an agent sends ACKs to the manager.
> 7) Explain why Wazuh uses NGINX and when to place HAProxy in front.
> 8) Register agents using the Wazuh API (if supported) and outline the steps.
> 9) List critical files when migrating a Wazuh server.
> 10) Describe the end-to-end alert flow from generation to UI, and how it changes if Indexer and Server are on different hosts.
> 11) Build a 2-node manager cluster and describe `client.keys` synchronization.

---

## Prerequisites
- TLS certificates created in `certs/` directory for Manager, Filebeat, Indexer and Dashboard.

`config.yml` used to create the certificates:
```yaml
nodes:
  indexer:
    - name: wazuh-indexer
      ip: "wazuh-indexer.local"

  server:
    - name: wazuh-manager
      ip: "wazuh-manager.local"

  dashboard:
    - name: wazuh-dashboard
      ip: "wazuh-dashboard.local"
```

Directory layout:
```
./wazuh-docker/
├── agents
│   ├── agent-centos
│   │   └── Dockerfile
│   └── agent-ubuntu
│       └── Dockerfile
├── certs
│   ├── dashboard
│   │   ├── dashboard-key.pem
│   │   ├── dashboard.pem
│   │   └── root-ca.pem
│   ├── filebeat
│   │   ├── filebeat-key.pem
│   │   ├── filebeat.pem
│   │   └── root-ca.pem
│   ├── indexer
│   │   ├── admin-key.pem
│   │   ├── admin.pem
│   │   ├── indexer-key.pem
│   │   ├── indexer.pem
│   │   └── root-ca.pem
│   ├── manager-1
│   │   ├── root-ca.pem
│   │   ├── server-key.pem
│   │   └── server.pem
│   └── manager-2
│       ├── root-ca.pem
│       ├── server-key.pem
│       └── server.pem
├── dashboard
│   ├── opensearch_dashboards.yml
│   └── wazuh.yml
├── docker-compose.yml
├── filebeat
│   └── config
│       ├── filebeat.yml
│       └── wazuh-template.json
├── haproxy
│   └── haproxy.cfg
├── indexer
│   └── config
│       └── opensearch.yml
├── manager
│   ├── docker-entrypoint.sh
│   └── Dockerfile
├── managers
│   ├── manager-1
│   │   └── config
│   │       └── ossec.conf
│   └── manager-2
│       └── config
│           └── ossec.conf
├── README.md
└── sync-certs.sh
```

---

## 1) Clone stable branch, compile, and install the Wazuh Manager on CentOS (Docker)

We compile Wazuh Manager from source in a multi‑stage Docker build based on CentOS. The compiled `/var/ossec` tree is then copied to a lean runtime image.

### 1.1 Manager Dockerfile (multi‑stage build)
Create `manager/Dockerfile`:

```dockerfile
FROM quay.io/centos/centos:stream9

ENV WAZUH_VERSION=4.12.0 \
    LANG=C.UTF-8 LC_ALL=C.UTF-8

# Basic dependencies + toolchain
RUN dnf -y update && \
    dnf -y swap curl-minimal curl && \
    dnf -y groupinstall "Development Tools" && \
    dnf -y install git wget cmake procps-ng expect \
                   python3-policycoreutils hostname selinux-policy-devel && \
    dnf clean all

# Clone source
WORKDIR /opt
RUN git clone --depth 1 --branch v${WAZUH_VERSION} https://github.com/wazuh/wazuh.git

# Unattended manager install via expect
WORKDIR /opt/wazuh
RUN cat <<'EOF' > /usr/local/bin/auto-install.exp
#!/usr/bin/expect -f
set timeout -1
spawn ./install.sh
expect {
    -re {Press ENTER to continue.*} { send "\r"; exp_continue }
    -re {\(en/.*\[en\]:}          { send "\r"; exp_continue }
    "What kind of installation"     { send "manager\r"; exp_continue }
    "Choose where to install Wazuh" { send "\r"; exp_continue }
    "Do you want to start Wazuh"    { send "y\r"; exp_continue }
    "Do you want e-mail notification?" { send "\r"; exp_continue }
    "Do you want to run the integrity check daemon?" { send "\r"; exp_continue }
    "Do you want to run the rootkit detection engine?" { send "\r"; exp_continue }
    "Do you want to add more IPs to the white list?"  { send "\r"; exp_continue }
    "Do you want to enable remote syslog (port 514 udp)?" { send "\r"; exp_continue }
    "Do you want to run the Auth daemon? (y/n)" { send "\r"; exp_continue }
    "Press ENTER to finish (maybe more information below)." { send "\r"; exp_continue }
    eof
}
EOF
RUN chmod +x /usr/local/bin/auto-install.exp && \
    /usr/local/bin/auto-install.exp && \
    rm -f /usr/local/bin/auto-install.exp

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 1514/udp 1515/tcp 1516/tcp 55000/tcp
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
```

### 1.2 Docker entrypoint script
Create `manager/docker-entrypoint.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

if [ -f /etc/wazuh/certs/server.pem ] && [ -f /etc/wazuh/certs/server-key.pem ]; then
  echo "[entrypoint] Installing API TLS certs for Wazuh..."
  cp /etc/wazuh/certs/server.pem     /var/ossec/api/configuration/ssl/server.crt
  cp /etc/wazuh/certs/server-key.pem /var/ossec/api/configuration/ssl/server.key
  chown wazuh:wazuh /var/ossec/api/configuration/ssl/server.crt /var/ossec/api/configuration/ssl/server.key
  chmod 644 /var/ossec/api/configuration/ssl/server.crt
  chmod 640 /var/ossec/api/configuration/ssl/server.key
fi

/var/ossec/bin/wazuh-control start

# 3. keep live
exec tail -F /var/ossec/logs/ossec.log
```
---

## 2. Add two agents to the manager: one CentOS and one Ubuntu

We run two agent containers and enroll them against the manager using `agent-auth` over TCP 1515.

### 2.1 CentOS Agent Dockerfile
Create `agent-centos/Dockerfile`:
```dockerfile
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

# Replace first <address>…</address> with manager host
sed -i "0,/<address>/{s|<address>.*</address>|<address>${MANAGER_HOST}</address>|}" \
    /var/ossec/etc/ossec.conf

# Register if no key present
if ! grep -q "$AGENT_NAME" /var/ossec/etc/client.keys 2>/dev/null; then
  /var/ossec/bin/agent-auth -m "$MANAGER_HOST" -p "$MANAGER_PORT" -A "$AGENT_NAME" || true
fi

exec /var/ossec/bin/wazuh-agentd -f
EOF
RUN chmod +x /usr/local/bin/entrypoint.sh

# only needed for active syslog
EXPOSE 1514/udp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
```

### 2.2 Ubuntu Agent Dockerfile

Create `agent-ubuntu/Dockerfile`:
```dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    WAZUH_MAJOR=4 \
    WAZUH_VERSION=4.12.0 \
    MANAGER_HOST=wazuh-manager \
    MANAGER_PORT=1515 \
    AGENT_NAME=""

# 1. Wazuh APT repository + dependencies
RUN apt-get update && \
    apt-get install -y curl gnupg lsb-release procps && \
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/${WAZUH_MAJOR}.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    apt-get install -y "wazuh-agent=${WAZUH_VERSION}-*" || apt-get install -y wazuh-agent && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# 2. Entry point: self-registration and foreground start
RUN cat <<'EOF' > /usr/local/bin/entrypoint.sh
#!/usr/bin/env bash
set -e
MANAGER_HOST=${MANAGER_HOST:-wazuh-manager}
MANAGER_PORT=${MANAGER_PORT:-1515}
AGENT_NAME=${AGENT_NAME:-$(hostname)}

# Replace first <address>…</address> with manager host
sed -i "0,/<address>/{s|<address>.*</address>|<address>${MANAGER_HOST}</address>|}" \
    /var/ossec/etc/ossec.conf

# Register if no key present
if ! grep -q "$AGENT_NAME" /var/ossec/etc/client.keys 2>/dev/null; then
  /var/ossec/bin/agent-auth -m "$MANAGER_HOST" -p "$MANAGER_PORT" -A "$AGENT_NAME" || true
fi

exec /var/ossec/bin/wazuh-agentd -f
EOF
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 1514/udp
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
```

### 2.3 Docker Compose Setup
Create `docker-compose.yml`:
```yaml
services:

  # Agents
  agent-centos:
    build: ./agent-centos
    environment:
      MANAGER_HOST: wazuh-manager
      MANAGER_PORT: "1515"
      AGENT_NAME: agent-centos
    depends_on:
      manager:
        condition: service_healthy
    networks:
      - wazuh-net
    restart: unless-stopped

  agent-ubuntu:
    build: ./agent-ubuntu
    environment:
      MANAGER_HOST: wazuh-manager
      MANAGER_PORT: "1515"
      AGENT_NAME: agent-ubuntu
    depends_on:
      manager:
        condition: service_healthy
    networks:
      - wazuh-net
    restart: unless-stopped

  # Manager
  manager:
    build: ./manager
    hostname: wazuh-manager
    ports:
      - "1514:1514/udp"
      - "1515:1515"
      - "1516:1516"
      - "55000:55000"
    volumes:
      - ./certs/manager:/etc/wazuh/certs:ro
      - wazuh-logs:/var/ossec/logs

    healthcheck:
      test: ["CMD-SHELL", "pgrep -x wazuh-monitord >/dev/null"]
      interval: 30s
      timeout: 5s
      start_period: 10s
      retries: 3
    networks:
      wazuh-net:
        aliases:
          - wazuh
          - wazuh-manager.local
          - wazuh-manager
    restart: unless-stopped

  # Indexer
  indexer:
    image: wazuh/wazuh-indexer:4.12.0
    container_name: wazuh-indexer
    environment:
      OPENSEARCH_JAVA_OPTS: "-Xms1g -Xmx1g"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    ports:
      - "9200:9200"
      - "9300:9300"
    volumes:
      - ./certs/indexer:/usr/share/wazuh-indexer/certs:ro
      - ./indexer/config/opensearch.yml:/usr/share/wazuh-indexer/opensearch.yml:ro

    networks:
      wazuh-net:
        aliases:
          - wazuh-indexer.local
          
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "curl --silent --fail --cacert /usr/share/wazuh-indexer/certs/root-ca.pem -u admin:admin --connect-timeout 2 --max-time 5 \"https://wazuh-indexer.local:9200/_cluster/health?wait_for_status=yellow&timeout=10s\" > /dev/null || exit 1"]
      interval: 15s
      timeout: 10s
      retries: 10
      start_period: 90s
      
  # Dashboard (OpenSearch Dashboards)
  dashboard:
    image: wazuh/wazuh-dashboard:4.12.0
    container_name: wazuh-dashboard
    depends_on:
      manager:
        condition: service_healthy
      indexer:
        condition: service_healthy
    environment:
      OPENSEARCH_HOSTS: '["https://wazuh-indexer.local:9200"]'
      OPENSEARCH_USERNAME: admin
      OPENSEARCH_PASSWORD: admin
      OPENSEARCH_SSL_VERIFICATIONMODE: full
      OPENSEARCH_SSL_CERTIFICATEAUTHORITIES: /etc/wazuh-dashboard/certs/root-ca.pem

      SERVER_SSL_ENABLED: "true"
      SERVER_SSL_CERTIFICATE: /etc/wazuh-dashboard/certs/dashboard.pem
      SERVER_SSL_KEY: /etc/wazuh-dashboard/certs/dashboard-key.pem

    ports:
      - "5601:5601"
    volumes:
      - wazuh-dashboard-data:/usr/share/wazuh-dashboard/data
      - ./dashboard/opensearch_dashboards.yml:/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml:ro
      - ./certs/dashboard:/etc/wazuh-dashboard/certs:ro
    networks:
      wazuh-net:
        aliases:
          - wazuh-dashboard.local
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "curl -sk -u admin:admin https://localhost:5601/api/status | grep -qi '\"state\":\"green\"'"]
      interval: 30s
      timeout: 10s
      retries: 5

  # Filebeat
  filebeat:
    image: docker.elastic.co/beats/filebeat-oss:7.10.2
    container_name: wazuh-filebeat
    user: root
    depends_on:
      manager:
        condition: service_healthy
    networks: [wazuh-net]
    restart: unless-stopped
    volumes:
      - ./filebeat/config/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - ./certs/filebeat:/usr/share/filebeat/certs:ro
      - wazuh-logs:/var/ossec/logs:ro
      - ./filebeat/config/wazuh-template.json:/etc/filebeat/wazuh-template.json:ro
    healthcheck:
      test: ["CMD-SHELL", "filebeat test config -e && filebeat test output -e"]
      interval: 15s
      timeout: 10s
      retries: 5
      start_period: 20s

volumes:
  wazuh-data:
  esdata:
  wazuh-logs:
  wazuh-dashboard-data:
networks:
  wazuh-net:
    driver: bridge
```
### 2.4 Build and Run
Run the following command in the directory containing `docker-compose.yml`:
```bash
docker compose up build

# Launch the stack
docker compose up -d
[+] Running 7/7
✅ Network wazuh-docker_wazuh-net         Created                                                                                                                                                                             0.0s 
✅ Container wazuh-indexer                Healthy                                                                                                                                                                            15.8s 
✅ Container wazuh-docker-manager-1       Healthy                                                                                                                                                                            10.7s 
✅ Container wazuh-docker-agent-ubuntu-1  Started                                                                                                                                                                            10.8s 
✅ Container wazuh-dashboard              Started                                                                                                                                                                            15.9s 
✅ Container wazuh-filebeat               Started                                                                                                                                                                            10.8s 
✅ Container wazuh-docker-agent-centos-1  Started                                                                                                                                                                            10.8s 
# Check container status
docker compose ps
NAME                          IMAGE                                         COMMAND                  SERVICE        CREATED         STATUS                   PORTS
wazuh-dashboard               wazuh/wazuh-dashboard:4.12.0                  "/entrypoint.sh"         dashboard      6 minutes ago   Up 6 minutes (healthy)   443/tcp, 0.0.0.0:5601->5601/tcp, [::]:5601->5601/tcp
wazuh-docker-agent-centos-1   wazuh-docker-agent-centos                     "/usr/local/bin/entr…"   agent-centos   6 minutes ago   Up 6 minutes             1514/udp
wazuh-docker-agent-ubuntu-1   wazuh-docker-agent-ubuntu                     "/usr/local/bin/entr…"   agent-ubuntu   6 minutes ago   Up 6 minutes             1514/udp
wazuh-docker-manager-1        wazuh-docker-manager                          "/usr/local/bin/dock…"   manager        6 minutes ago   Up 6 minutes (healthy)   0.0.0.0:1515-1516->1515-1516/tcp, [::]:1515-1516->1515-1516/tcp, 0.0.0.0:1514->1514/udp, [::]:1514->1514/udp, 0.0.0.0:55000->55000/tcp, [::]:55000->55000/tcp
wazuh-filebeat                docker.elastic.co/beats/filebeat-oss:7.10.2   "/usr/local/bin/dock…"   filebeat       6 minutes ago   Up 6 minutes (healthy)   
wazuh-indexer                 wazuh/wazuh-indexer:4.12.0                    "/entrypoint.sh open…"   indexer        6 minutes ago   Up 6 minutes (healthy)   0.0.0.0:9200->9200/tcp, [::]:9200->9200/tcp, 0.0.0.0:9300->9300/tcp, [::]:9300->9300/tcp
```

### 2.5 Verify connectivity & enrollment
After the containers are up, verify that the agents have successfully enrolled with the manager. 

On the **manager** container:
```bash
# List registered agents (client.keys)
docker exec -it $(docker ps -qf name=manager) /var/ossec/bin/agent_control -lc
Wazuh agent_control. List of available agents:
   ID: 000, Name: wazuh-manager (server), IP: 127.0.0.1, Active/Local
   ID: 001, Name: agent-centos, IP: any, Active
   ID: 002, Name: agent-ubuntu, IP: any, Active

# Dump client.keys entries
docker exec -it $(docker ps -qf name=manager) bash -c 'cat /var/ossec/etc/client.keys'
001 agent-centos any 1a1d7be9f402c4a0aa6afa414d24f136e1bb2b2e669530f07836720baaf3e497
002 agent-ubuntu any 1e546aa503343e060400bd39482355ab3c36975805b7e6ad21530c7e99c0229d
```

On each **agent**:
```bash
# Confirm connection messages to manager
docker exec -it wazuh-docker-agent-centos-1 grep -iE 'connected|connected to the server' /var/ossec/logs/ossec.log || true
2025/08/10 16:44:00 wazuh-agentd: INFO: (4102): Connected to the server ([wazuh-manager]:1514/tcp).

wazuh exec -it wazuh-docker-agent-ubuntu-1 grep -iE 'connected|connected to the server' /var/ossec/logs/ossec.log || true
2025/08/10 16:44:00 wazuh-agentd: INFO: (4102): Connected to the server ([wazuh-manager]:1514/tcp).
```

On the **filebeat**:
```bash
docker exec -it wazuh-filebeat bash -lc 'getent hosts wazuh-indexer.local'
172.18.0.3      wazuh-indexer.local

docker exec -it wazuh-filebeat bash -lc 'filebeat test config -e'
2025-08-10T17:25:42.480Z	INFO	instance/beat.go:645	Home path: [/usr/share/filebeat] Config path: [/usr/share/filebeat] Data path: [/usr/share/filebeat/data] Logs path: [/usr/share/filebeat/logs]
2025-08-10T17:25:42.480Z	INFO	instance/beat.go:653	Beat ID: 26b2d91b-887b-4535-8e98-257d052ad099
2025-08-10T17:25:42.480Z	INFO	[beat]	instance/beat.go:981	Beat info	{"system_info": {"beat": {"path": {"config": "/usr/share/filebeat", "data": "/usr/share/filebeat/data", "home": "/usr/share/filebeat", "logs": "/usr/share/filebeat/logs"}, "type": "filebeat", "uuid": "26b2d91b-887b-4535-8e98-257d052ad099"}}}
2025-08-10T17:25:42.480Z	INFO	[beat]	instance/beat.go:990	Build info	{"system_info": {"build": {"commit": "aacf9ecd9c494aa0908f61fbca82c906b16562a8", "libbeat": "7.10.2", "time": "2021-01-12T22:10:33.000Z", "version": "7.10.2"}}}
2025-08-10T17:25:42.480Z	INFO	[beat]	instance/beat.go:993	Go runtime info	{"system_info": {"go": {"os":"linux","arch":"amd64","max_procs":22,"version":"go1.14.12"}}}
2025-08-10T17:25:42.481Z	INFO	[beat]	instance/beat.go:997	Host info	{"system_info": {"host": {"architecture":"x86_64","boot_time":"2025-08-10T14:49:57Z","containerized":false,"name":"2b4a6864b44c","ip":["127.0.0.1/8","::1/128","172.18.0.6/16"],"kernel_version":"6.14.0-27-generic","mac":["a6:ef:b1:cc:14:c0"],"os":{"family":"redhat","platform":"centos","name":"CentOS Linux","version":"7 (Core)","major":7,"minor":9,"patch":2009,"codename":"Core"},"timezone":"UTC","timezone_offset_sec":0,"id":"3d458769eadb4ca1ac689c5da40af2bf"}}}
2025-08-10T17:25:42.481Z	INFO	[beat]	instance/beat.go:1026	Process info	{"system_info": {"process": {"capabilities": {"inheritable":null,"permitted":["chown","dac_override","fowner","fsetid","kill","setgid","setuid","setpcap","net_bind_service","net_raw","sys_chroot","mknod","audit_write","setfcap"],"effective":["chown","dac_override","fowner","fsetid","kill","setgid","setuid","setpcap","net_bind_service","net_raw","sys_chroot","mknod","audit_write","setfcap"],"bounding":["chown","dac_override","fowner","fsetid","kill","setgid","setuid","setpcap","net_bind_service","net_raw","sys_chroot","mknod","audit_write","setfcap"],"ambient":null}, "cwd": "/usr/share/filebeat", "exe": "/usr/share/filebeat/filebeat", "name": "filebeat", "pid": 6867, "ppid": 0, "seccomp": {"mode":"filter","no_new_privs":false}, "start_time": "2025-08-10T17:25:42.360Z"}}}
2025-08-10T17:25:42.481Z	INFO	instance/beat.go:299	Setup Beat: filebeat; Version: 7.10.2
2025-08-10T17:25:42.481Z	INFO	eslegclient/connection.go:99	elasticsearch url: https://wazuh-indexer.local:9200
2025-08-10T17:25:42.481Z	INFO	[publisher]	pipeline/module.go:113	Beat name: 2b4a6864b44c
Config OK

docker exec -it wazuh-filebeat bash -lc 'filebeat test output -e'
2025-08-10T17:26:31.120Z	INFO	instance/beat.go:645	Home path: [/usr/share/filebeat] Config path: [/usr/share/filebeat] Data path: [/usr/share/filebeat/data] Logs path: [/usr/share/filebeat/logs]
2025-08-10T17:26:31.120Z	INFO	instance/beat.go:653	Beat ID: 26b2d91b-887b-4535-8e98-257d052ad099
2025-08-10T17:26:31.120Z	INFO	[index-management]	idxmgmt/std.go:184	Set output.elasticsearch.index to 'filebeat-7.10.2' as ILM is enabled.
2025-08-10T17:26:31.120Z	INFO	eslegclient/connection.go:99	elasticsearch url: https://wazuh-indexer.local:9200
elasticsearch: https://wazuh-indexer.local:9200...
  parse url... OK
  connection...
    parse host... OK
    dns lookup... OK
    addresses: 172.18.0.3
    dial up... OK
  TLS...
    security: server's certificate chain verification is enabled
    handshake... OK
    TLS version: TLSv1.3
    dial up... OK
2025-08-10T17:26:31.127Z	INFO	[esclientleg]	eslegclient/connection.go:314	Attempting to connect to Elasticsearch version 7.10.2
  talk to server... OK
  version: 7.10.2
```

On the **Indexer**:
```bash
# Basic health (adjust CA path/user as per your lab)
curl -sS --cacert certs/indexer/root-ca.pem -u admin:admin \
  --resolve wazuh-indexer.local:9200:127.0.0.1 \
  https://wazuh-indexer.local:9200/_cluster/health?pretty
{
  "cluster_name" : "wazuh-indexer",
  "status" : "green",
  "timed_out" : false,
  "number_of_nodes" : 1,
  "number_of_data_nodes" : 1,
  "discovered_master" : true,
  "discovered_cluster_manager" : true,
  "active_primary_shards" : 10,
  "active_shards" : 10,
  "relocating_shards" : 0,
  "initializing_shards" : 0,
  "unassigned_shards" : 0,
  "delayed_unassigned_shards" : 0,
  "number_of_pending_tasks" : 0,
  "number_of_in_flight_fetch" : 0,
  "task_max_waiting_in_queue_millis" : 0,
  "active_shards_percent_as_number" : 100.0
}

curl -sS --cacert certs/indexer/root-ca.pem -u admin:admin \
  --resolve wazuh-indexer.local:9200:127.0.0.1 \
  "https://wazuh-indexer.local:9200/_cat/nodes?v"
ip         heap.percent ram.percent cpu load_1m load_5m load_15m node.role node.roles                                        cluster_manager name
172.18.0.3           50          64   4    0.34    0.80     1.58 dimr      cluster_manager,data,ingest,remote_cluster_client *               node-1

curl -sS --cacert certs/indexer/root-ca.pem -u admin:admin \
  --resolve wazuh-indexer.local:9200:127.0.0.1 \
  "https://wazuh-indexer.local:9200/_cat/indices/wazuh-alerts-4.x*?v"
health status index                       uuid                   pri rep docs.count docs.deleted store.size pri.store.size
green  open   wazuh-alerts-4.x-2025.08.10 AMQLVkNeTvqmYti3WnQpEw   3   0         22            0    101.4kb        101.4kb
```
---

## 3) RIDs (counters) — what they are and how to enable/inspect

The RIDs are monotonic sequence counters used by the *secure* channel between **agent ↔ manager** to ensure **ordering** and **anti‑replay/deduplication** of messages.  

**Where they live:** both ends persist files under `/var/ossec/queue/rids/`.  
- On the **manager**: one file per agent id (e.g., `001`, `002`) holding the **last RID received** from that agent, plus a **global** `sender_counter` with the last RID the manager **sent**.
- On the **agent**: a `sender_counter` (last RID **sent** to the manager) and a file named after the manager id (usually `001`) containing the **last RID received** from the manager.

**Why needed:** to reject old/replayed/duplicate packets and to preserve ordering across restarts (state is persisted on disk).

**How enabled:** RIDs are always active when using `<remote><connection>secure</connection>` (default in Wazuh 4.x). Verify in `ossec.conf`.

```xml
<remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
</remote>
```

### 3.1 Verify RIDs are working

### 3.1.1 On the manager
- **List RID files and metadata**
```bash
docker exec -it wazuh-docker-manager-1 bash -lc '
  ls -l /var/ossec/queue/rids
'
total 12
-rw-r--r-- 1 wazuh wazuh 7 Aug 11 01:41 001
-rw-r--r-- 1 wazuh wazuh 7 Aug 11 00:41 002
-rw-r--r-- 1 wazuh wazuh 7 Aug 11 01:51 sender_counter
```
- **Show the latest counter line from each file**
```bash
docker exec -it wazuh-docker-manager-1 bash -lc '
  for f in /var/ossec/queue/rids/*; do
    printf -- "%s -> " "$f"
    tail -n1 "$f"
    printf "\n"
  done
'
/var/ossec/queue/rids/001 -> 0:1734:
/var/ossec/queue/rids/002 -> 0:1124:
/var/ossec/queue/rids/sender_counter -> 0:5458:
```

The loop prints the last line of every RID file on the manager. You see one file per agent (`001`, `002`) and a global `sender_counter`.
### 3.1.2 On an agent
- **List RID files and metadata**
```bash
#Agent 1 (Ubuntu)
docker exec -it wazuh-docker-agent-ubuntu-1 bash -lc '
    ls -l /var/ossec/queue/rids
'
total 8
-rw-r--r-- 1 wazuh wazuh 7 Aug 11 11:50 001
-rw-r--r-- 1 wazuh wazuh 7 Aug 11 12:04 sender_counter

#Agent 2 (CentOS)
docker exec -it wazuh-docker-agent-centos-1 bash -lc '
    ls -l /var/ossec/queue/rids
'
total 8
-rw-r--r-- 1 wazuh wazuh 7 Aug 11 11:50 002
-rw-r--r-- 1 wazuh wazuh 7 Aug 11 12:03 sender_counter
```

- **Show the latest counter line from each file**
```bash
# Agent 1 (Ubuntu)
docker exec -it wazuh-docker-agent-ubuntu-1 bash -lc '
  for f in /var/ossec/queue/rids/*; do
    printf -- "%s -> " "$f"
    tail -n1 "$f"
    printf "\n"
  done 
'
/var/ossec/queue/rids/001 -> 0:5837:
/var/ossec/queue/rids/sender_counter -> 0:2040:

# Agent 2 (CentOS)
docker exec -it wazuh-docker-agent-centos-1 bash -lc '
    for f in /var/ossec/queue/rids/*; do
        printf -- "%s -> " "$f"
        tail -n1 "$f"
        printf "\n"
        done
'
/var/ossec/queue/rids/002 -> 0:5838:
/var/ossec/queue/rids/sender_counter -> 0:2045:
```

### 3.2 Safe reset (only if needed)

1. Stop the affected **agent** and the **manager**.
2. Remove the agent’s RID file on **both** sides:

```bash
# Agent
rm -f /var/ossec/queue/rids/*
# Manager (replace 001 with the real agent ID)
rm -f /var/ossec/queue/rids/001
```

3. Start the manager, then the agent; counters will re‑initialize.

---

## 4) Real‑time File Integrity Monitoring (FIM) in Wazuh 4.x

> How can I add a file to Wazuh’s configuration to monitor it in **real time** and where do I see the resulting alert when that file changes?

On first run, the agent’s `wazuh-syscheckd` builds/loads a baseline database of each monitored path (hashes: MD5/SHA‑1/SHA‑256; size; owner/group; perms; mtime; inode on UNIX; attributes on Windows).  

```xml
<agent_config>
  <syscheck>
    <directories realtime="yes" report_changes="yes">/etc</directories>
    <directories whodata="yes" report_changes="yes">/etc/ssh/sshd_config</directories>
    <whodata><provider>audit</provider></whodata>
  </syscheck>
</agent_config>
```

- **Periodic mode**: at each scan (`frequency`/`scan_time`/`scan_day`), it compares current metadata against the baseline and emits events for create/modify/delete.
- **Real‑time mode**: subscribes to OS notifications and processes events immediately while updating the baseline:
    - Linux: inotify (directory‑level); single‑file via parent dir + `restrict`, or via `whodata`.
    - Windows: native directory change notifications; single‑file via parent dir + `restrict`, or via `whodata`.
- **Who‑data enrichment** (Linux/Windows only): adds user, process, and PID that performed the change.
    - Linux providers: `<whodata><provider>audit</provider></whodata>` (default) or `<provider>ebpf</provider>` (kernel ≥ 5.8).
    - Windows: the agent auto‑configures **Local Audit Policy** and **SACL** on monitored objects to generate Security Log events, which FIM parses.
- **Diff storage when** (text files only):
    - Linux: `/var/ossec/queue/diff/local/`
    - macOS: `/Library/Ossec/queue/diff/local/`
    - Windows: `C:\Program Files (x86)\ossec-agent\queue\diff\local\`

> **Important**: The `realtime` attribute enables continuous monitoring on **Windows and Linux only**. On macOS, FIM runs on a schedule (periodic mode). Use `frequency`, `scan_time`, and `scan_day` to tune cadence.

### 4.1 Linux Agent Example

- Real‑time: `realtime="yes"` on directories (inotify). For a single file use parent dir + `restrict`, or use `whodata="yes"` directly on the file path.
- Who‑data: `<whodata><provider>audit|ebpf</provider></whodata>`.
- Example:

```xml
<agent_config>
  <syscheck>
    <directories realtime="yes" report_changes="yes">/etc</directories>
    <directories whodata="yes" report_changes="yes">/etc/ssh/sshd_config</directories>
    <whodata><provider>audit</provider></whodata>
  </syscheck>
</agent_config>
```

### 4.2 Windows Agent Example
- Real‑time: supported with `realtime="yes"` on directories. Single file via parent dir + `restrict`, or `whodata="yes"` on the file path.
- Who‑data: when enabled, the agent configures Local Audit Policy + SACL on the target to emit Security log events (for example 4663/4656), which FIM correlates to `syscheck.audit`.
- Config path: `C:\Program Files (x86)\ossec-agent\ossec.conf`. Restart: `Restart-Service -Name wazuh`.
- Example (single file):

```xml
<agent_config>
  <syscheck>
    <!-- Realtime on parent dir, narrowed to one file -->
    <directories realtime="yes" restrict="^hosts$" report_changes="yes">C:\Windows\System32\drivers\etc</directories>

    <!-- Or who-data directly on the file -->
    <directories whodata="yes" report_changes="yes">C:\Windows\System32\drivers\etc\hosts</directories>
  </syscheck>
</agent_config>
```

### 4.3 macOS Agent Example
- **Periodic scans only**: `realtime` and `whodata` are not supported on macOS agents in 4.x.
- Config path: `/Library/Ossec/etc/ossec.conf`. Restart: `/Library/Ossec/bin/wazuh-control restart`.
- Tune schedule:

```xml
<agent_config>
  <syscheck>
    <frequency>1800</frequency>        <!-- every 30 minutes -->
    <scan_on_start>yes</scan_on_start>
    <directories report_changes="yes">/etc</directories>
  </syscheck>
</agent_config>
```
---

## 5) Enroll a third agent using agent enrollment; identify the default agent ID assigned by Authd.

### 5.1 Agent enrollment (`wazuh-authd`) works

The agent initiates a **one-time secure enrollment** to the manager on **TCP/1515** (`wazuh-authd`). The manager 
validates the request (optionally with a shared password), **creates or reuses** an agent entry, and sends back the agent’s **key**.
Once enrolled, the agent uses **TCP/1514** to send logs/events to the manager (`wazuh-remoted`). 

**ID assignment:** by default the manager allocates the **next free numeric ID** (`001`, `002`, `003`, …).

### 5.2 Manager-side configuration
1. **Enable/confirm** in `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <!-- Enable this if you want a shared password: -->
    <!-- <use_password>yes</use_password> -->
  </auth>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
  </remote>
</ossec_config>
```
2. **(Optional) Set an enrollment password** (required if `<use_password>yes</use_password>`):

```bash
echo 'StrongEnrollPass' | sudo tee /var/ossec/etc/authd.pass >/dev/null
sudo chmod 600 /var/ossec/etc/authd.pass
```

3. **Restart the manager** and confirm listeners:

```bash
sudo /var/ossec/bin/wazuh-control restart
sudo /var/ossec/bin/wazuh-control status
sudo ss -tlnp | egrep '1514|1515'
```

4. **Firewall**: allow **1515/TCP** (enrollment) and **1514/TCP** (agent data channel) to the manager.

### 5.3 Enroll a remote agent
On the **agent host** (with Wazuh agent installed):

```bash
# Replace values with your environment
MANAGER_HOST=<manager FQDN or IP>
AUTHD_PORT=1515
AGENT_NAME="ubuntu-agent-03"

# Without password (if <use_password> is not enabled)
sudo /var/ossec/bin/agent-auth -m "$MANAGER_HOST" -p "$AUTHD_PORT" -A "$AGENT_NAME" 

# With password (if the manager requires it)
# sudo /var/ossec/bin/agent-auth -m "$MANAGER_HOST" -p "$AUTHD_PORT" -A "$AGENT_NAME -P 'StrongEnrollPass'"

# Start/restart the agent service
sudo systemctl restart wazuh-agent 2>/dev/null || sudo /var/ossec/bin/wazuh-control restart
```

>**Notes:**  
>Use `-I <ip>` if you need to register a specific source IP (NAT/multi-homed hosts).  
>After successful enrollment, data flows to **TCP/1514** automatically.

### 5.4 Enroll a local agent (installed on the manager host)
It is common to also monitor the manager’s OS with a **local agent**. The manager itself is **ID**, while the local agent will receive a **normal** ID (e.g., `003` if it’s the third).

On the manager host (where `wazuh-agent` is installed):

```bash
sudo /var/ossec/bin/agent-auth -m 127.0.0.1 -p 1515 -A manager-host-agent -P 'StrongEnrollPass'
sudo systemctl restart wazuh-agent 2>/dev/null || sudo /var/ossec/bin/wazuh-control restart
```

### 5.5 Verify from the manager

List agents and confirm the **assigned ID** (the third should be `` if `001` and `002` already exist):

```bash
# Show agents connection status
sudo /var/ossec/bin/agent_control -lc
```

## 5.6 Manual method (without `authd`)

You can connect agents **without** `wazuh-authd`. This is useful in isolated environments or when you do not want to expose **1515/TCP**.

1. **On the manager** (create and extract a key):
```bash
sudo /var/ossec/bin/manage_agents
# a) Add agent -> enter name/IP (you can use 'any')
# e) Extract key -> copy the resulting key
```

2. **On the agent** (import the key and start):
```bash
sudo /var/ossec/bin/manage_agents
# i) Import key -> paste the key from the manager
sudo systemctl restart wazuh-agent 2>/dev/null || sudo /var/ossec/bin/wazuh-control restart
```
With this method, only **TCP/1514** to the manager is required. The **ID** is assigned when you **Add agent** on the manager (again, sequential: `001`, `002`, `003`, …).

Verify from the manager with:
```bash
  sudo /var/ossec/bin/agent_control -lc
```

---

## 6) Keepalive cadence, reconnect behavior, and manager disconnection threshold

Agents send a keepalive every **10 seconds** by default (`<notify_time>`). If a connection fails, the agent waits **60 seconds** before retrying (`<time-reconnect>`).  
The manager flags an agent as **disconnected** if it receives no keepalives within **10 minutes** by default (`<agents_disconnection_time>`). Always set this **greater than `notify_time`**.

### 6.1 What is the keepalive?
- A lightweight **heartbeat** sent from **agent → manager** over the normal data channel (**TCP/1514** by default).
- Confirms liveness, allows the manager to update agent status, and helps drive timing of some manager-side actions (e.g., showing *Last keep alive* in `agent_control -lc`).
- Independent of enrollment: keepalives start **after** the agent is enrolled and connected.

### 6.2 Agent-side settings (defaults and tuning)
Configure these in the **agent** at `/var/ossec/etc/ossec.conf` under `<client>`:

```xml
<ossec_config>
  <client>
    <!-- How often the agent sends a keepalive (seconds). Default: 10 -->
    <notify_time>10</notify_time>

    <!-- How long the agent waits before trying to reconnect after a failure (seconds). Default: 60 -->
    <time-reconnect>60</time-reconnect>

    <server>
      <address>WAZUH_MANAGER_FQDN_OR_IP</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>
</ossec_config>
```

### 6.3 Manager-side policy: when is an agent “disconnected”?
Set on the **manager** in `/var/ossec/etc/ossec.conf` (global scope):

```xml
<ossec_config>
  <!-- Time window with no keepalives after which the agent is considered disconnected. -->
  <agents_disconnection_time>10m</agents_disconnection_time>
</ossec_config>
```

---

## 7) Explain why Wazuh uses NGINX and when to place HAProxy in front.

**NGINX** is commonly used as a **reverse proxy / TLS offloader** to publish the **Wazuh Dashboard** (and optionally the **Wazuh API**) securely on the Internet/LAN with hardening headers.  
**HAProxy** (or any L4 TCP load balancer) is used to **distribute agent traffic** (1514/TCP) across manager nodes and keep **automatic failover**; enrollment (1515/TCP) is often pinned to the master.  
Both are **optional**, but **a TCP load balancer in front of the managers is recommended** when you have many agents or a multi-node manager cluster.  

### 7.1 What Wazuh uses out of the box (4.x)

- Core Wazuh services:
    - **Manager** (e.g., `wazuh-remoted` on **1514/TCP**, `wazuh-authd` on **1515/TCP**).
    - **Wazuh API** on **55000/TCP**.
    - **Wazuh Dashboard** (web UI) on **5601/TCP**.
- None of these strictly **require** NGINX or HAProxy to run. However, most production setups place:
    - **NGINX** in front of the **Dashboard** (and sometimes the **API**) for TLS, SSO/headers, and web hardening.
    - **HAProxy/NGINX-stream** in front of the **Manager** nodes for agent load balancing and failover.

### 7.2 When to use NGINX
NGINX acts as a **reverse proxy** and **TLS termination** point for HTTP(S) services in Wazuh:
- **Publish the Dashboard** safely on 443 with Let’s Encrypt/ACME, HSTS, and security headers.
- **Offload TLS** from the Dashboard process and centralize certificates/renewals.
- **Optional API exposure**: proxy the **Wazuh API (55000/TCP)** if you want a single HTTPS entry point with unified auth and IP ACLs.
- **Rate limiting & headers**: mitigate brute-force on the Dashboard login, add CSP/Referrer-Policy, etc.

> You can also use **NGINX stream** (L4) to proxy TCP services, but for heavy agent traffic **HAProxy** is usually preferred.

### 7.3 When to use HAProxy
Use **HAProxy** (or a similar **L4 TCP** load balancer) when you need to **scale** or provide **high availability** for agents:
- **Balance agent data channel** (**1514/TCP**) across **multiple managers**.
- **Health checks** and **automatic failover** if a manager goes down.
- **Stickiness** (e.g., `balance source`) so a given agent tends to reconnect to the same node.
- **Enrollment routing** (**1515/TCP**): usually forwarded to the **master** node only, while data (**1514/TCP**) goes to the whole pool.

### 7.4 Recommendations for production
- **Recommendation**: if you have **> a few hundred agents** or **any cluster**, use a **TCP load balancer** (HAProxy). It simplifies agent configs and gives fast failover.
- **Keep ****1515**** simple**: send enrollment to the **master**; let the cluster replicate metadata.
- **Timeouts matter**: keep TCP timeouts ≥ agent keepalive cadence; avoid dropping long-lived idle sessions.
- **Certificates**: terminate TLS for web (Dashboard/API) at **NGINX**; keep internal manager traffic on private networks.
- **Do not expose 1514/1515 to the Internet** unless absolutely necessary; prefer private links or VPN.

## 8) Register agents using the Wazuh API and outline the steps

This method is equivalent to the “manual” enrollment (no `authd`), but **automatable over HTTPS**. It’s useful when you don’t want to expose **TCP/1515** or when you need to **pre‑provision** agent IDs/keys at scale.

### 8.1 Prerequisites

- **Wazuh API reachable** (default **TCP/55000**), with valid credentials (user with RBAC permissions to manage agents).
- On the **agent**: Wazuh Agent installed, network reachability to the manager on **TCP/1514**.
- `curl` and (optionally) `jq` on the workstation you’ll use to call the API.

### 8.2 Authenticate and obtain a token

```bash
# Variables
API="https://<manager_or_vip>:55000"
USER="<api_user>"
PASS="<api_password>"

# Authenticate and capture JWT token
TOKEN=$(curl -sk -u "$USER:$PASS" -X POST "$API/security/user/authenticate" | jq -r .data.token)
echo "$TOKEN" | sed 's/.\{10\}$/.../'

#Example output:
TOKEN=$(curl -sk -u wazuh-wui:wazuh-wui -X POST https://127.0.0.1:55000/security/user/authenticate | jq -r .data.token)
echo "$TOKEN" | sed 's/.\{10\}$/.../'
eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3YXp1aCIsImF1ZCI6IldhenVoIEFQSSBSRVNUIiwibmJmIjoxNzU0OTUzMTUxLCJleHAiOjE3NTQ5NTQwNTEsInN1YiI6IndhenVoLXd1aSIsInJ1bl9hcyI6ZmFsc2UsInJiYWNfcm9sZXMiOlsxXSwicmJhY19tb2RlIjoid2hpdGUifQ.ARLhxZOFaKAZzkxWb4bOV8ON0nJnF9uuDcQzi-GBnT2WFH2X80Sf-2zyTLAtGSGAF877vsNsJ3gI-G0wJAq1SJHLAJPk8jTIZrwDgLa-ouhYRQEPcn61tZp4rv4vnsCH_ua23X6t-tSwoJ2dB3Rjj53OYk027iu8lnL_am...
```

### 8.3 Create (register) the agent via API
Send a **POST** to `/agents` with a name (and optional IP). The API returns the **agent **`` and its ``.

```bash
AGENT_NAME="ubuntu-agent-03"
AGENT_IP="any"      # or a specific IP if you want to pin it

RESP=$(curl -sk -X POST "$API/agents" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"name\":\"$AGENT_NAME\",\"ip\":\"$AGENT_IP\"}")

echo "$RESP" | jq

AGENT_ID=$(echo "$RESP" | jq -r '.data.id')
AGENT_KEY=$(echo "$RESP" | jq -r '.data.key')

echo "ID=$AGENT_ID"; echo "KEY=${AGENT_KEY:0:16}..."

##Example output:
RESP=$(curl -sk -X POST 'https://127.0.0.1:55000/agents' \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"ubuntu-agent-03","ip":"any"}')
  
echo "$RESP" | jq
{
  "data": {
    "id": "003",
    "key": "MDAzIHVidW50dS1hZ2VudC0wMyBhbnkgMTkyZWZlZmNkNjc5YjRmZDdkYTc1NzQ2ZmIyM2UzNmQ4OTdhODlmNjhhZmU0ZmRhYWEyYzRlZmM5YzQzZTEwYQ=="
  },
  "error": 0
}

AGENT_ID=$(echo "$RESP" | jq -r '.data.id')
AGENT_KEY=$(echo "$RESP" | jq -r '.data.key')
echo "ID=$AGENT_ID"; echo "KEY=${AGENT_KEY:0:16}..."
ID=003
KEY=MDAzIHVidW50dS1h...

```

> If the name already exists, the request may fail or return a conflict. Use a unique naming scheme (e.g., hostname + suffix) or clean old entries first.

### 8.4 (Optional) Assign the agent to a group

Depending on your 4.x minor version, you can assign groups with either a per‑agent endpoint or a batch call. Two common patterns:

**A) Single agent → single group** (typical):

```bash
GROUP="linux-baseline"
# Some versions expose a per-agent group assignment endpoint like:
# PUT /agents/<AGENT_ID>/group/<GROUP>
# or a POST under /agents/groups with a body referencing the agent ID.

# Example:
curl -sk -X PUT "$API/agents/$AGENT_ID/group/$GROUP" \
  -H "Authorization: Bearer $TOKEN" | jq
```

**B) Batch add to group** (when available):

```bash
curl -sk -X POST "$API/agents/groups" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"group\":\"$GROUP\",\"agents_list\":[\"$AGENT_ID\"]}"
```

### 8.5 Import the key on the agent and start it

On the **agent host**:

```bash
# Import the key (recommended: interactive tool)
sudo /var/ossec/bin/manage_agents <<EOF
I
$AGENT_KEY
Q
EOF

# Point the agent to the manager and ensure TCP/1514
sudo sed -i '0,/<address>/{s|<address>.*</address>|<address><MANAGER_FQDN_OR_IP></address>|}' /var/ossec/etc/ossec.conf

# Start/restart the agent
sudo systemctl restart wazuh-agent 2>/dev/null || sudo /var/ossec/bin/wazuh-control restart
```
> You can also craft the line in `/var/ossec/etc/client.keys` manually, but using `manage_agents` is safer and version‑friendly.

## 9) List critical files when migrating a Wazuh server.

### 9.1 Core manager (must‑have)
- **/var/ossec/etc/ossec.conf** — Main configuration (remote/authd/cluster/modules/outputs). Losing this means defaults or broken outputs.
- **/var/ossec/etc/client.keys** — **Agent ID ⇄ key mapping**. This prevents re‑enrollment; treat as the most critical secret. Owner/perm: typically `root:ossec` and `640`.
- **/var/ossec/etc/internal_options.conf** and **/var/ossec/etc/local_internal_options.conf** — Performance/engine tunings. Only present if you’ve customized.
- **/var/ossec/etc/authd.pass** — Enrollment password for `wazuh-authd` if `<use_password>yes</use_password>`.

### 9.2 Rules, decoders, and lists (custom content)
- **/var/ossec/etc/rules/local_rules.xml** — Your custom rules.
- **/var/ossec/etc/decoders/local_decoder.xml** — Your custom decoders.
- **/var/ossec/etc/lists/** — Custom CDB lists / data files.
- **Any additional XML/CDB** added under `etc/{rules,decoders,lists}`.
> Do **not** copy the built‑in vendor ruleset under `/var/ossec/ruleset/` unless you intentionally modified it (not recommended). Keep customizations under `etc/`.

### 9.3 Centralized config and agent groups
- **/var/ossec/etc/shared/** — Centralized configs (`agent.conf` global and group‑specific), SCA content you distribute, etc.
- **/var/ossec/queue/agent-groups/** — Runtime state of **group membership** per agent ID. Optional to migrate, but keeping it avoids having to reassign groups.

### 9.4 Integrations, modules, and Active Response
- **/var/ossec/integrations/** — Integration scripts (Slack, VT, webhooks) and their configs.
- **/var/ossec/wodles/** — Cloud/3rd‑party modules (AWS, GCP, Azure, O365, osquery), including any custom additions.
- **/var/ossec/active-response/bin/** and **/var/ossec/etc/active-response/** — Custom Active Response scripts and policies.
- **/var/ossec/etc/agentless/** (if you use agentlessd), **/var/ossec/etc/lua/** (if you use Lua scripts).

### 9.5 Wazuh API (config, TLS, RBAC)
- **/var/ossec/api/configuration/api.yaml** — API settings (port, TLS, limits).
- **/var/ossec/api/configuration/ssl/** — API certificate, key, and CA.
- **/var/ossec/api/configuration/security/** — **API users, roles, and policies (RBAC)**. Missing this forces you to recreate users/roles.

### 9.6 Certificates and TLS material
- Ensure you migrate any **custom CA/cert/key** paths referenced by `ossec.conf`, integrations, or outputs.
- If you terminate TLS elsewhere (reverse proxy), capture that proxy’s certificates/config as well.

### 9.7 Filebeat on the manager (if co‑located)
- **/etc/filebeat/filebeat.yml** — Output endpoints/pipelines/paths.
- **/etc/filebeat/certs/** — CA/client certs for TLS to Indexer.
- **/etc/filebeat/filebeat.keystore** — Secrets used by Filebeat (if any).

### 9.8 Logs and history (optional but useful)
- **/var/ossec/logs/alerts/** — `alerts.json` and rotations; historical alerts.
- **/var/ossec/logs/ossec.log** — Troubleshooting after migration.
> Not required for functionality, but useful for audit and regression analysis.

### 9.9 What **not** to migrate (rebuilds automatically)
- **/var/ossec/queue/** (e.g., `agent-info/`, `alerts/`, `diff/`, `ossec/`) — Runtime/ephemeral state regenerated at startup.
- **/var/ossec/ruleset/** (vendor content) — Reinstalled with packages; migrate only if you knowingly customized it (prefer moving edits to `etc/`).

### 9.10 Backup (source server)
Use `tar` or `rsync` preserving ownership, ACLs, and permissions. Example with `tar`:
```bash
sudo tar --xattrs --acls --preserve-permissions -czf /root/wazuh-manager-backup.tgz \
  /var/ossec/etc/ossec.conf \
  /var/ossec/etc/client.keys \
  /var/ossec/etc/internal_options.conf \
  /var/ossec/etc/local_internal_options.conf \
  /var/ossec/etc/rules /var/ossec/etc/decoders /var/ossec/etc/lists \
  /var/ossec/etc/shared \
  /var/ossec/integrations /var/ossec/wodles \
  /var/ossec/active-response/bin /var/ossec/etc/active-response \
  /var/ossec/api/configuration \
  /var/ossec/etc/authd.pass \
  /etc/filebeat 2>/dev/null || true
```
> Remove `/etc/filebeat` if Filebeat is not installed on the same host.

### 9.11 Restore (target server)
```bash
# Stop manager before restore
sudo systemctl stop wazuh-manager 2>/dev/null || sudo /var/ossec/bin/wazuh-control stop

# Extract preserving owners/perms
sudo tar -xzf /root/wazuh-manager-backup.tgz -C /

# Fix ownership/perms for sensitive files
sudo chown -R root:ossec /var/ossec/etc
sudo chmod 640 /var/ossec/etc/client.keys

# Start services
sudo systemctl start wazuh-manager 2>/dev/null || sudo /var/ossec/bin/wazuh-control start
```

### 9.12 Post‑migration verification checklist
```bash
# Manager processes
sudo /var/ossec/bin/wazuh-control status

# API (if hosted here)
curl -sk -u <user:pass> https://127.0.0.1:55000/security/user/authenticate | jq -r .data.token | head -c 20; echo

# Enrollment and data channels
sudo ss -tlnp | egrep '1514|1515'

# Agents (IDs, connectivity, keepalives)
sudo /var/ossec/bin/agent_control -l
sudo /var/ossec/bin/agent_control -lc

# Filebeat (if co-located)
sudo systemctl status filebeat
sudo grep -E 'ERROR|WARN' /var/log/filebeat/filebeat -n | tail -n 50 2>/dev/null || true
```

### 9.13 Notes and gotchas
- **`client.keys` is the crown jewel** — losing it means re‑enrolling agents (or re‑injecting keys).
- **RBAC/API** — without `api/configuration/security/` you’ll lose users/roles; migrate it.
- **Groups** — if you skip `etc/shared/` and `queue/agent-groups/`, be ready to reassign groups via API/UI.
- **TLS/Certificates** — keep CA/certs/keys consistent with configured hostnames/FQDNs; mismatches will break TLS.
- **Containers** — prefer **bind‑mounted volumes** for `/var/ossec` and `/etc/filebeat` so migration is a file‑level copy. If using `docker cp`, recreate containers with those volumes mounted on the new host after the copy.


## 10) Describe the end-to-end alert flow from generation to UI, and how it changes if Indexer and Server are on different hosts.

### 10.1 End-to-End Flow (Generation → UI)

**Agent → Manager (ingest)**

  - Agent modules (e.g., **logcollector**, **syscheckd/FIM**, **rootcheck**, **SCA**, etc.) produce events.
  - `ossec-agentd` sends events to the **Manager** via **1514/TCP** (TLS). Enrollment happens via **1515/TCP** to `authd`.

**Manager (decode, correlate, alert)**

  - `ossec-remoted` receives events and hands them to `ossec-analysisd`.
  - `analysisd` runs **predecoders → decoders → rules**, leveraging lists (CDB), GeoIP, FTS if enabled.
  - On rule match:
    - Writes structured alerts to (and/or `alerts.log`).
    - Optionally persists raw/normalized events to `` as `archives.log` / `archives.json` (if `logall` / `logall_json` enabled).
    - May trigger **Active Responses**.

**Shipper (Filebeat) → Indexer (store & search)**

  - **Filebeat** (Wazuh module) tails (and `archives.json` if present), handling rotation and retries.
  - Ships to **Wazuh Indexer (OpenSearch/Elasticsearch)** over **HTTPS 9200** using the configured credentials/TLS CA and (when configured) client certs.
  - The Indexer applies the **Wazuh ingest pipeline** (field normalization, GeoIP, enrichments) and indexes into daily indices, typically:
    - `wazuh-alerts-4.x-YYYY.MM.DD`
    - `wazuh-archives-4.x-YYYY.MM.DD` (if archives are shipped)

**UI (Dashboard) + API (Manager)**

  - **Wazuh Dashboard** queries the **Indexer** to render security events, timelines, and visuals.
  - For agent status, tasks, RBAC, and configuration, the Dashboard talks to the **Wazuh API** on the Manager (**55000/TCP**).
  - The UI is effectively a **merge of data sources**: events from Indexer + metadata/state from the API.

#### 10.2 Flow Diagram 
```mermaid
---
config:
  layout: dagre
  theme: neo-dark
---
flowchart TD
    subgraph A["Agent"]
        A1["Agent modules"]
        A2["ossec-agentd"]
    end
    subgraph M["Manager / Wazuh Server"]
        M0["authd - enrollment 1515/TCP"]
        M1["ossec-remoted"]
        M2["ossec-analysisd predecoders → decoders → rules"]
        M3["alerts.json"]
        M4["archives.json archives.log"]
    end
    subgraph F["Shipper"]
        F1["Filebeat - Wazuh module Harvester + Pipeline"]
    end
    subgraph I["Wazuh Indexer"]
        I1["Ingest Pipelinenormalize, GeoIP, enrich"]
        I2[("wazuh-alerts-4.x-YYYY.MM.DD")]
        I3[("wazuh-archives-4.x-YYYY.MM.DD")]
    end
    subgraph D["UI"]
        D1["Wazuh Dashboard"]
        D2["Wazuh API - Manager 55000/TCP"]
    end
    A1 --> A2
    A2 -- 1514/TLS --> M1
    A2 -- 1515/TCP (enroll) --> M0
    M1 --> M2
    M2 -- write --> M3
    M2 -. optional .-> M4
    M3 -- tail --> F1
    F1 -- 9200/HTTPS --> I1
    I1 --> I2
    I1 -. if shipped .-> I3
    D1 -- query events --> I2
    D1 -. archives views .-> I3
    D1 -- agent status / RBAC --> D2
```

### 10.3 If Indexer and Server are on different hosts
**The logical pipeline remains the same.** Differences are operational/networking:

- **Connectivity & TLS**
    - Filebeat (on the Manager host) must reach the remote **Indexer** on **9200/HTTPS** with valid CA and hostnames (CN/SAN).
    - **Dashboard** must be configured to talk to the **Indexer** (events) and to the **Manager API** (55000/TCP) simultaneously.
- **Ports to open**
    - Agents → Manager: **1514/TCP** (events), **1515/TCP** (enrollment).
    - Manager (Filebeat) → Indexer: **9200/TCP** (HTTPS).
    - Users → Dashboard: **5601/TCP**.
    - Dashboard → Manager API: **55000/TCP**.
- **Time & DNS**
    - Keep **NTP synchronized** across hosts; time skew can hide “recent” events in time-filtered views.
    - Ensure forward/reverse **DNS** or `/etc/hosts` align with certificate hostnames.

---

## 11) Build a 2-node manager cluster and describe `client.keys` synchronization

### 11.1 What a Wazuh cluster is (and why 2 nodes)
A Wazuh **cluster** is a set of managers that coordinate through an internal backbone (TCP **1516**) to behave like one logical manager. With a **2‑node (master/worker)** setup you get:

- **High availability**: if the master goes down, agents can still send data to the worker.
- **Horizontal capacity**: traffic (agent events and enrollments) is shared.
- **Single point of administration**: the master is the “source of truth” for agent enrollments and shared content.

In this lab:

- `manager-1` runs as **master**.
- `manager-2` runs as **worker**.
- Both communicate on the cluster port **1516** (only inside the Docker network).

### 11.2 Why HAProxy here (and its role)
Agents need two TCP services:

- **1515**: enrollment (`agent-auth`)
- **1514**: event channel (agent → manager)

Instead of configuring agents with two manager hostnames, we put **HAProxy (`wazuh-lb`)** in front of both managers and give agents a **single DNS name** (`wazuh-lb`). Benefits:

- **Simple agent config** (one address to rule them all).
- **Automatic failover / load sharing** across `manager-1` and `manager-2`.
- Agents can **enroll against any node** via the LB; the cluster ensures the master records the enrollment and replicates it.

> In this compose, the LB only exposes ports on the **Docker network** (no host‑port mapping). If you later need external agents, publish LB ports (e.g., `51514:1514`, `51515:1515`).

### 11.3 Update Flow Chart to include HAProxy and 2 managers
```mermaid
---
config:
  layout: dagre
  theme: neo-dark
---
flowchart TD
  %% Two-node Wazuh with HAProxy
  subgraph A["Agent"]
    A1["Agent modules"]
    A2["ossec-agentd"]
  end

  subgraph LB["HAProxy (wazuh-lb)"]
    LB1514["frontend 1514/TLS (events)"]
    LB1515["frontend 1515/TCP (enrollment)"]
  end

  subgraph M1["Manager-1 (Master)"]
    M10["authd - enrollment 1515/TCP"]
    M11["ossec-remoted"]
    M12["ossec-analysisd predecoders → decoders → rules"]
    M13["alerts.json"]
    M14["archives.json archives.log"]
    M1K["client.keys"]
  end

  subgraph M2["Manager-2 (Worker)"]
    M20["authd - enrollment 1515/TCP"]
    M21["ossec-remoted"]
    M22["ossec-analysisd predecoders → decoders → rules"]
    M23["alerts.json"]
    M24["archives.json archives.log"]
    M2K["client.keys"]
  end

  subgraph F["Shipper"]
    F1["Filebeat - Wazuh module Harvester + Pipeline"]
  end

  subgraph I["Wazuh Indexer"]
    I1["Ingest Pipeline (normalize, GeoIP, enrich)"]
    I2[("wazuh-alerts-4.x-YYYY.MM.DD")]
    I3[("wazuh-archives-4.x-YYYY.MM.DD")]
  end

  subgraph D["UI"]
    D1["Wazuh Dashboard"]
    D2["Wazuh API - Manager 55000/TCP"]
  end

  %% Paths
  A1 --> A2

  %% Enrollment path
  A2 -- "1515/TCP (enroll)" --> LB1515
  LB1515 --> M10
  LB1515 --> M20

  %% Events path
  A2 -- "1514/TLS" --> LB1514
  LB1514 --> M11
  LB1514 --> M21

  %% Manager internal processing
  M11 --> M12
  M21 --> M22
  M12 -- write --> M13
  M12 -. optional .-> M14
  M22 -- write --> M23
  M22 -. optional .-> M24

  %% Filebeat tails both managers
  M13 -- tail --> F1
  M23 -- tail --> F1

  %% Send to indexer
  F1 -- 9200/HTTPS --> I1
  I1 --> I2
  I1 -. if shipped .-> I3

  %% Dashboard queries
  D1 -- query events --> I2
  D1 -. archives views .-> I3
  D1 -- agent status / RBAC --> D2

  %% Cluster sync of enrollments
  M1K <-. "cluster 1516/TCP" .-> M2K
```

### 11.4 Validate the cluster is healthy
From the managers:

```bash
# Master
docker compose exec manager-1 bash -lc '
  echo "== cluster.log (last 50) ==" && tail -n 50 /var/ossec/logs/cluster.log
  echo "== node role ==" && grep -E "node_name|node_type|Cluster name" /var/ossec/logs/cluster.log | tail -n 5
'

# Worker
docker compose exec manager-2 bash -lc '
  echo "== cluster.log (last 50) ==" && tail -n 50 /var/ossec/logs/cluster.log
  echo "== connection to master ==" && grep -i "connected" /var/ossec/logs/cluster.log | tail -n 5
'

# Cluster CLI (if present)
docker compose exec manager-1 /var/ossec/bin/cluster_control -i
Cluster name: wazuh-lab

Last completed synchronization for connected nodes (1):
    wazuh-manager-2 (172.18.0.4): Integrity check: 2025-08-13T11:50:38.036159Z | Integrity sync: 2025-08-13T10:59:24.568118Z | Agents-info: 2025-08-13T11:50:37.682241Z | Agent-groups: n/a | Agent-groups full: n/a | Last keep alive: 2025-08-13T11:50:15.786753Z.
    
docker compose exec manager-1 /var/ossec/bin/cluster_control -l
NAME             TYPE    VERSION  ADDRESS                    
wazuh-manager-1  master  4.12.0   wazuh-manager-1.wazuh.lab  
wazuh-manager-2  worker  4.12.0   172.18.0.4      
```

### 11.5 Validate HAProxy with managers & agents
verify that **HAProxy** is correctly routing traffic to both managers:
```bash
docker run --rm --network wazuh-docker_wazuh-net busybox sh -lc 'nslookup wazuh-lb && nc -zvw2 wazuh-lb 1515 && echo \"OK LB:1515\" && nc -zvw2 wazuh-lb 1514 && echo \"OK LB:1514\"'
Server:		127.0.0.11
Address:	127.0.0.11:53

Non-authoritative answer:

Non-authoritative answer:
Name:	wazuh-lb
Address: 172.18.0.7

wazuh-lb (172.18.0.7:1515) open
"OK LB:1515"
wazuh-lb (172.18.0.7:1514) open
"OK LB:1514"
```

### 11.6 How agent enrollment propagates (`client.keys` sync)
- Agents enroll by running **`agent-auth`** against the LB (`wazuh-lb:1515`).
- The request may hit either node; the **worker automatically forwards** the enrollment to the **master**.
- The **master writes/updates** `/var/ossec/etc/client.keys` with the new agent entry.
- The cluster **replicates** `client.keys` from **master → worker**, so **both nodes** can authenticate that agent on **1514**.

**Verify replication** after enrolling an agent:
```bash
# Look for the agent entry on both managers
docker compose exec manager-1 bash -lc "grep -n ' agent-ubuntu ' /var/ossec/etc/client.keys || true"
2:002 agent-ubuntu any f502f6d7b7040368048af7f12e02a78b4ed41fd0f029580334fb221a3d67cfc7

docker compose exec manager-2 bash -lc "grep -n ' agent-ubuntu ' /var/ossec/etc/client.keys || true"
2:002 agent-ubuntu any f502f6d7b7040368048af7f12e02a78b4ed41fd0f029580334fb221a3d67cfc7

# The files should be identical
docker compose exec manager-1 md5sum /var/ossec/etc/client.keys
9030cead7c8337f957dc48ff2dfd14eb  /var/ossec/etc/client.keys

docker compose exec manager-2 md5sum /var/ossec/etc/client.keys
9030cead7c8337f957dc48ff2dfd14eb  /var/ossec/etc/client.keys
```

### 11.7 Where this ties into your Compose & Agent image
- **Managers**: `manager-1` (master) and `manager-2` (worker) share the same cluster name and see each other on **1516** within `wazuh-net`.
- **HAProxy (`wazuh-lb`)**: frontends **1514/1515** and distributes to both managers—agents only need `MANAGER_HOST=wazuh-lb`.
- **Agent Dockerfile/entrypoint**: the agent self‑registers via:

```bash
/var/ossec/bin/agent-auth -m "$MANAGER_HOST" -p "$MANAGER_PORT" -A "$AGENT_NAME"
```

This hits the LB; the cluster then ensures `client.keys` is written on the master and **synced** to the worker.