#!/bin/bash
# Gateway entrypoint: keep container alive.
# Snort and iptables are started via post_deploy_commands.

exec tail -f /dev/null
