#!/bin/bash
# Start SSH server and keep container alive.
/usr/sbin/sshd
exec tail -f /dev/null
