FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    sshpass \
    nmap \
    curl \
    hydra \
    smbclient \
    iproute2 \
    iputils-ping \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

COPY config/passwords.txt /opt/passwords.txt

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
