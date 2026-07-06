FROM vulnerables/cve-2017-7494

# Base image uses Debian Jessie (EOL); point to archive mirror
RUN sed -i 's|http://security.debian.org|http://archive.debian.org/debian-security|g' /etc/apt/sources.list && \
    sed -i 's|http://deb.debian.org/debian|http://archive.debian.org/debian|g' /etc/apt/sources.list && \
    sed -i '/jessie-updates/d' /etc/apt/sources.list && \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid

RUN apt-get update && apt-get install -y --allow-unauthenticated --no-install-recommends \
    iproute2 \
    iptables \
    smbclient \
    && rm -rf /var/lib/apt/lists/*

COPY config/smb.conf /etc/samba/smb.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 139 445

ENTRYPOINT ["/entrypoint.sh"]
