#!/bin/sh
set -e

PERMISSIVE_MODE="${PERMISSIVE_MODE:-1}"

mkdir -p /tmp/php-uploads
chmod 0777 /tmp/php-uploads

mkdir -p /data/in /data/out /data/logs

# PERMISSIVE_MODE allows adjusting security levels
# For actual operation, it is recommended to set PERMISSIVE_MODE to 0
if [ "$PERMISSIVE_MODE" = "1" ]; then
  chmod -R 0777 /data
else
  chgrp -R www-data /data 2>/dev/null || true
  find /data -type d -exec chmod 2775 {} \; || true
  find /data -type f -exec chmod 0664 {} \; || true
fi

ls -ld /data /data/in /data/out /data/logs 2>/dev/null || true
id 2>/dev/null || true

exec "$@"
