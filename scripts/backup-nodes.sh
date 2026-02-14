#!/usr/bin/env bash
# ------------------------------------------------------------------
# Backup LDK node state from both droplets to local machine.
#
# What gets backed up:
#   keys_seed              — 64-byte master entropy (never changes)
#   ldk_node_data.sqlite   — channel state, peer data, monitors
#   ldk_node.log           — optional, useful for debugging
#
# Run this AFTER any channel-state-changing operation:
#   - open-channel
#   - receiving/sending a payment
#   - closing a channel
#
# Usage:
#   ./scripts/backup-nodes.sh
#   ./scripts/backup-nodes.sh /path/to/backup/dir
# ------------------------------------------------------------------
set -euo pipefail

BACKUP_ROOT="${1:-./backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"

CREATOR_IP="${CONDUIT_CREATOR_IP:?Set CONDUIT_CREATOR_IP}"
BUYER_IP="${CONDUIT_BUYER_IP:?Set CONDUIT_BUYER_IP}"
CREATOR_STORAGE="/tmp/conduit-creator"
BUYER_STORAGE="/tmp/conduit-buyer"

echo "=== Conduit Node Backup ==="
echo "Timestamp: ${TIMESTAMP}"
echo "Backup dir: ${BACKUP_DIR}"
echo ""

mkdir -p "${BACKUP_DIR}/creator"
mkdir -p "${BACKUP_DIR}/buyer"

echo "[1/2] Backing up creator node (${CREATOR_IP})..."
scp -q "root@${CREATOR_IP}:${CREATOR_STORAGE}/keys_seed" "${BACKUP_DIR}/creator/"
scp -q "root@${CREATOR_IP}:${CREATOR_STORAGE}/ldk_node_data.sqlite" "${BACKUP_DIR}/creator/"
scp -q "root@${CREATOR_IP}:${CREATOR_STORAGE}/ldk_node.log" "${BACKUP_DIR}/creator/" 2>/dev/null || true
echo "  -> creator backed up"

echo "[2/2] Backing up buyer node (${BUYER_IP})..."
scp -q "root@${BUYER_IP}:${BUYER_STORAGE}/keys_seed" "${BACKUP_DIR}/buyer/"
scp -q "root@${BUYER_IP}:${BUYER_STORAGE}/ldk_node_data.sqlite" "${BACKUP_DIR}/buyer/"
scp -q "root@${BUYER_IP}:${BUYER_STORAGE}/ldk_node.log" "${BACKUP_DIR}/buyer/" 2>/dev/null || true
echo "  -> buyer backed up"

# Also keep a symlink to the latest backup
ln -sfn "${TIMESTAMP}" "${BACKUP_ROOT}/latest"

echo ""
echo "Done. Files:"
ls -lhR "${BACKUP_DIR}"
echo ""
echo "Latest symlink: ${BACKUP_ROOT}/latest -> ${TIMESTAMP}"
