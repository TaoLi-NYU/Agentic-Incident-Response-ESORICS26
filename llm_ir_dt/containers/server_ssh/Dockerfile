FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd

# Create vulnerable users with weak passwords
RUN useradd -m -s /bin/bash admin && echo "admin:password123" | chpasswd
RUN echo "root:toor" | chpasswd

COPY config/sshd_config /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
