FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    openssh-server \
    iproute2 \
    iptables \
    iputils-ping \
    python3 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd

COPY config/index.html /var/www/html/index.html
COPY vulnerable_upload_server.py /opt/vulnerable_upload_server.py
COPY vulnerable_diag_server.py /opt/vulnerable_diag_server.py

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 22

ENTRYPOINT ["/entrypoint.sh"]
