#!/usr/bin/env bash
# One-time setup: install the systemd service file on a node.
#
# Usage:
#   ./deploy/setup-systemd.sh <service-file>
#
# Example:
#   ./deploy/setup-systemd.sh conduit-creator.service
#
# Run this ON the target node (or pipe via ssh).
# The .service file must already be present in the current directory or
# provided as an absolute path.

set -euo pipefail

SERVICE_FILE="${1:?Usage: $0 <service-file>}"
SERVICE_NAME="$(basename "$SERVICE_FILE" .service)"

if [ ! -f "$SERVICE_FILE" ]; then
    echo "Error: $SERVICE_FILE not found"
    exit 1
fi

echo "==> Installing $SERVICE_FILE as $SERVICE_NAME.service"
cp "$SERVICE_FILE" /etc/systemd/system/
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

echo "==> Stopping any existing nohup process..."
# Try to find and kill existing conduit processes matching this service
case "$SERVICE_NAME" in
    conduit-creator)
        pkill -f "conduit-setup.*storage-dir.*/var/lib/conduit-creator" || true
        ;;
    conduit-buyer)
        pkill -f "conduit-setup.*storage-dir.*/var/lib/conduit-buyer" || true
        ;;
    conduit-seeder)
        pkill -f "conduit-setup.*storage-dir.*/var/lib/conduit-seeder[^2]" || true
        ;;
    conduit-seeder2)
        pkill -f "conduit-setup.*storage-dir.*/var/lib/conduit-seeder2" || true
        ;;
    conduit-registry)
        pkill -f "conduit-registry" || true
        ;;
esac

sleep 2

echo "==> Starting $SERVICE_NAME via systemd..."
systemctl start "$SERVICE_NAME"
systemctl status "$SERVICE_NAME" --no-pager

echo ""
echo "Done. Monitor with:"
echo "  journalctl -u $SERVICE_NAME -f"
