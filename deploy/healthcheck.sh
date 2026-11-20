#!/bin/sh
# Cron-able monitor: alerts when `nostracle status` reports a problem.
#   */5 * * * * /var/lib/nostracle/healthcheck.sh
# Set ALERT_CMD to anything that reads a message on stdin (mail, ntfy, a nostr DM tool...).
cd /var/lib/nostracle
out=$(/usr/local/bin/nostracle -c config.toml status 2>&1) || \
  printf 'nostracle unhealthy on %s\n%s\n' "$(hostname)" "$out" | ${ALERT_CMD:-cat}
