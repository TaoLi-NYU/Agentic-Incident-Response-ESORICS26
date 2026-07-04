FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 \
    iproute2 \
    build-essential \
    autotools-dev \
    wget \
    ca-certificates \
    xz-utils \
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
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
