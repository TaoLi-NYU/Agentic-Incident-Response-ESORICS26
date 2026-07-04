#!/bin/bash
# Start Apache and keep container alive.
apachectl start
exec tail -f /dev/null
