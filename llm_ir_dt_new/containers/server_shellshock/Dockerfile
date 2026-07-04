FROM debian:buster

ENV DEBIAN_FRONTEND=noninteractive

# Buster is EOL; point to the archive mirror
RUN sed -i 's|http://deb.debian.org/debian|http://archive.debian.org/debian|g' /etc/apt/sources.list && \
    sed -i 's|http://deb.debian.org/debian-security|http://archive.debian.org/debian-security|g' /etc/apt/sources.list && \
    sed -i '/buster-updates/d' /etc/apt/sources.list

RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 \
    iproute2 \
    iptables \
    build-essential \
    autotools-dev \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Enable CGI module
RUN a2enmod cgi

# Download and compile vulnerable bash 4.2 (without shellshock patches)
# Replace config.guess/config.sub so ./configure works on aarch64
RUN cd /tmp && \
    wget -q https://ftp.gnu.org/gnu/bash/bash-4.2.tar.gz && \
    tar xzf bash-4.2.tar.gz && \
    cd bash-4.2 && \
    cp /usr/share/misc/config.guess support/config.guess && \
    cp /usr/share/misc/config.sub support/config.sub && \
    ./configure --prefix=/usr && \
    make && \
    cp bash /bin/bash && \
    cd / && rm -rf /tmp/bash-4.2*

COPY config/vulnerable.cgi /usr/lib/cgi-bin/vulnerable
RUN chmod +x /usr/lib/cgi-bin/vulnerable

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
