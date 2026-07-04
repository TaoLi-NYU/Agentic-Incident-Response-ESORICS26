#!/bin/bash
# Start Samba and keep container alive.
mkdir -p /srv/share
chmod 0777 /srv/share
/usr/sbin/smbd --no-process-group
exec tail -f /dev/null
