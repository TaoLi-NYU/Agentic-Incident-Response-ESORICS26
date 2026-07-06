#!/bin/bash
# Start Samba and keep container alive.
mkdir -p /srv/share /var/log/samba
chmod 0777 /srv/share
/usr/local/samba/sbin/smbd -s /etc/samba/smb.conf --no-process-group &
exec tail -f /dev/null
