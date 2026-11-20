#!/bin/sh
# Snapshot the oracle db (and archive) with a timestamp. Run from cron, e.g.
#   */10 * * * * /var/lib/nostracle/backup.sh /var/lib/nostracle/data /backup/nostracle
# Copy the key ONCE to offline storage; it never changes.
# Ship BACKUP_DIR off the machine (rsync, restic, ...).
set -eu
DATA_DIR=${1:?data dir}
BACKUP_DIR=${2:?backup dir}
mkdir -p "$BACKUP_DIR"
ts=$(date -u +%Y%m%dT%H%M%SZ)
# events.json is replaced atomically by rename, so a plain copy is consistent.
cp "$DATA_DIR/events.json" "$BACKUP_DIR/events-$ts.json"
[ -f "$DATA_DIR/events.archive.jsonl" ] && cp "$DATA_DIR/events.archive.jsonl" "$BACKUP_DIR/events.archive.jsonl"
# keep 7 days of snapshots
find "$BACKUP_DIR" -name 'events-*.json' -mtime +7 -delete
