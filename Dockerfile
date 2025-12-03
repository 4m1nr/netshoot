# ==========================================
# Stage 1: Fetch binary tools
# ==========================================
FROM debian:stable-slim as fetcher
COPY build/fetch_binaries.sh /tmp/fetch_binaries.sh

RUN apt-get update && apt-get install -y \
  curl \
  wget

RUN /tmp/fetch_binaries.sh

# ==========================================
# Stage 2: Build Go backend
# ==========================================
FROM golang:1.21-alpine AS backend-builder

WORKDIR /app

COPY backend/go.mod ./
RUN go mod download

COPY backend/ .
RUN CGO_ENABLED=0 GOOS=linux go build -o netshoot-server ./cmd/server/

# ==========================================
# Stage 3: Build React Native web frontend
# ==========================================
FROM node:20-alpine AS frontend-builder

WORKDIR /app

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ .
RUN npx expo export --platform web --output-dir dist

# ==========================================
# Stage 4: Final image with all components
# ==========================================
FROM alpine:3.22.0

RUN set -ex \
    && echo "http://dl-cdn.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories \
    && echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories \
    && echo "http://dl-cdn.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories \
    && apk update \
    && apk upgrade \
    && apk add --no-cache \
    apache2-utils \
    bash \
    bind-tools \
    bird \
    bridge-utils \
    busybox-extras \
    conntrack-tools \
    curl \
    dhcping \
    drill \
    ethtool \
    file\
    fping \
    iftop \
    iperf \
    iperf3 \
    iproute2 \
    ipset \
    iptables \
    iptraf-ng \
    iputils \
    ipvsadm \
    httpie \
    jq \
    libc6-compat \
    liboping \
    ltrace \
    mtr \
    net-snmp-tools \
    netcat-openbsd \
    nftables \
    ngrep \
    nmap \
    nmap-nping \
    nmap-scripts \
    openssl \
    py3-pip \
    py3-setuptools \
    scapy \
    socat \
    speedtest-cli \
    openssh \
    oh-my-zsh \
    strace \
    tcpdump \
    tcptraceroute \
    trippy \
    tshark \
    util-linux \
    vim \
    git \
    zsh \
    websocat \
    swaks \
    perl-crypt-ssleay \
    perl-net-ssleay \
    nginx \
    supervisor

# Installing ctop - top-like container monitor
COPY --from=fetcher /tmp/ctop /usr/local/bin/ctop

# Installing calicoctl
COPY --from=fetcher /tmp/calicoctl /usr/local/bin/calicoctl

# Installing termshark
COPY --from=fetcher /tmp/termshark /usr/local/bin/termshark

# Installing grpcurl
COPY --from=fetcher /tmp/grpcurl /usr/local/bin/grpcurl

# Installing fortio
COPY --from=fetcher /tmp/fortio /usr/local/bin/fortio

# Installing Go backend API server
COPY --from=backend-builder /app/netshoot-server /usr/local/bin/netshoot-server

# Installing web frontend
COPY --from=frontend-builder /app/dist /var/www/html

# Setting User and Home
USER root
WORKDIR /root
ENV HOSTNAME netshoot

# ZSH Themes
RUN curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh | sh
RUN git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
RUN git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k
COPY zshrc .zshrc
COPY motd motd

# Fix permissions for OpenShift and tshark
RUN chmod -R g=u /root
RUN chown root:root /usr/bin/dumpcap

# Nginx configuration for frontend with API proxy
RUN mkdir -p /etc/nginx/http.d
COPY <<EOF /etc/nginx/http.d/default.conf
server {
    listen 80;
    server_name localhost;
    root /var/www/html;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

# Supervisor configuration to run both services
RUN mkdir -p /etc/supervisor.d
COPY <<EOF /etc/supervisor.d/netshoot.ini
[supervisord]
nodaemon=true
logfile=/var/log/supervisord.log
pidfile=/var/run/supervisord.pid

[program:backend]
command=/usr/local/bin/netshoot-server
autostart=true
autorestart=true
stdout_logfile=/var/log/backend.log
stderr_logfile=/var/log/backend-error.log
environment=PORT="8080"

[program:nginx]
command=/usr/sbin/nginx -g "daemon off;"
autostart=true
autorestart=true
stdout_logfile=/var/log/nginx-access.log
stderr_logfile=/var/log/nginx-error.log
EOF

# Create startup script
COPY <<EOF /usr/local/bin/start-netshoot.sh
#!/bin/bash
# Netshoot startup script

MODE=\${1:-shell}

case "\$MODE" in
    web)
        echo "Starting Netshoot with Web UI..."
        echo "  - Web UI: http://localhost:80"
        echo "  - API: http://localhost:8080"
        exec /usr/bin/supervisord -c /etc/supervisord.conf
        ;;
    api)
        echo "Starting Netshoot API server only..."
        echo "  - API: http://localhost:8080"
        exec /usr/local/bin/netshoot-server
        ;;
    shell|*)
        echo "Starting Netshoot shell..."
        exec /bin/zsh
        ;;
esac
EOF
RUN chmod +x /usr/local/bin/start-netshoot.sh

# Expose ports
# 80 - Web UI
# 8080 - API
EXPOSE 80 8080

# Default command - run shell (original behavior)
# Use: docker run -it netshoot (for shell)
# Use: docker run -p 80:80 -p 8080:8080 netshoot web (for web UI + API)
# Use: docker run -p 8080:8080 netshoot api (for API only)
CMD ["zsh"]
ENTRYPOINT ["/usr/local/bin/start-netshoot.sh"]
