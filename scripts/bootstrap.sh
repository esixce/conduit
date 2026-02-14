#!/usr/bin/env bash
# Bootstrap both Conduit droplets: install Rust, build deps, deploy code, build.
#
# Usage:
#   ./scripts/bootstrap.sh <CREATOR_IP> <BUYER_IP>
#
# Assumes:
#   - You have SSH access as root to both IPs
#   - You're running this from the conduit/ project root

set -euo pipefail

CREATOR_IP="${1:?Usage: $0 <CREATOR_IP> <BUYER_IP>}"
BUYER_IP="${2:?Usage: $0 <CREATOR_IP> <BUYER_IP>}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

REMOTE_SETUP='#!/bin/bash
set -euo pipefail

echo "==> Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq build-essential pkg-config libssl-dev > /dev/null

echo "==> Installing Rust..."
if ! command -v cargo &> /dev/null; then
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi
source "$HOME/.cargo/env"

echo "==> Building conduit..."
cd /root/conduit
cargo build --release 2>&1 | tail -5

echo "==> Done. Binaries at /root/conduit/target/release/"
'

bootstrap_node() {
    local IP="$1"
    local NAME="$2"

    echo ""
    echo "================================================================"
    echo "  Bootstrapping $NAME ($IP)"
    echo "================================================================"

    echo "==> Uploading code..."
    # Exclude target/ and .git/ to keep transfer small
    rsync -az --progress \
        --exclude 'target/' \
        --exclude '.git/' \
        --exclude 'docs/' \
        "$PROJECT_DIR/" "root@${IP}:/root/conduit/"

    echo "==> Running setup on remote..."
    ssh "root@${IP}" "$REMOTE_SETUP"
}

bootstrap_node "$CREATOR_IP" "conduit-creator"
bootstrap_node "$BUYER_IP" "conduit-buyer"

echo ""
echo "================================================================"
echo "  Both nodes bootstrapped successfully."
echo "================================================================"
echo ""
echo "Creator: ssh root@${CREATOR_IP}"
echo "Buyer:   ssh root@${BUYER_IP}"
echo ""
echo "Next steps:"
echo "  1. On buyer:   cargo run -p conduit-setup -- address"
echo "  2. Fund at:    https://faucet.mutinynet.com"
echo "  3. On buyer:   cargo run -p conduit-setup -- open-channel \\"
echo "                   --node-id <CREATOR_NODE_ID> \\"
echo "                   --addr ${CREATOR_IP}:9735 \\"
echo "                   --amount 100000"
echo "  4. Wait ~30s for channel confirmation"
echo "  5. Run tests:  CONDUIT_INTEGRATION=1 cargo test -p conduit-core \\"
echo "                   --test integration_lightning -- --nocapture"
