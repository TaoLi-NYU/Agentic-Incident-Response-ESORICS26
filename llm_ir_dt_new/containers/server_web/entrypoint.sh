#!/bin/bash
# Start SSH and Nginx, then keep container alive.
/usr/sbin/sshd
nginx -g "daemon on;"
exec tail -f /dev/null
