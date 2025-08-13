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