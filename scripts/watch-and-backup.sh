#!/usr/bin/env bash
# ------------------------------------------------------------------
# Run ON a droplet to watch for sqlite changes and copy to a
# remote backup location after each state change.
#
# Uses inotifywait (install: apt install inotify-tools)
# Falls back to polling if inotify is unavailable.
#
# Usage (on the droplet):
#   nohup ./watch-and-backup.sh /var/lib/conduit-creator user@backup-host:/backups/creator &
#   nohup ./watch-and-backup.sh /var/lib/conduit-buyer   user@backup-host:/backups/buyer &
# ------------------------------------------------------------------
set -euo pipefail

NODE_DIR="${1:?Usage: $0 <node-dir> <remote-dest>}"
REMOTE_DEST="${2:?Usage: $0 <node-dir> <remote-dest>}"
SQLITE_FILE="${NODE_DIR}/ldk_node_data.sqlite"
POLL_INTERVAL=5  # seconds, used if inotifywait is unavailable

do_backup() {
    echo "[$(date -Iseconds)] Channel state changed — backing up to ${REMOTE_DEST}"
    scp -q "${SQLITE_FILE}" "${REMOTE_DEST}/" 2>&1 || echo "  WARNING: backup failed"
}

if command -v inotifywait &>/dev/null; then
    echo "Using inotifywait to watch ${SQLITE_FILE}"
    while true; do
        inotifywait -qq -e modify -e close_write "${SQLITE_FILE}" 2>/dev/null
        # Small debounce — LDK may do multiple writes in quick succession
        sleep 1
        do_backup
    done
else
    echo "inotifywait not found — falling back to polling every ${POLL_INTERVAL}s"
    LAST_HASH=""
    while true; do
        CURRENT_HASH=$(sha256sum "${SQLITE_FILE}" 2>/dev/null | cut -d' ' -f1 || echo "")
        if [[ -n "${CURRENT_HASH}" && "${CURRENT_HASH}" != "${LAST_HASH}" ]]; then
            if [[ -n "${LAST_HASH}" ]]; then
                do_backup
            fi
            LAST_HASH="${CURRENT_HASH}"
        fi
        sleep "${POLL_INTERVAL}"
    done
fi
