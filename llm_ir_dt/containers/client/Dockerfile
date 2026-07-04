FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
# Dockerfile：构建攻击客户端，安装 sshpass、nmap、curl、hydra、smbclient、ping、nc 等工具
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
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
