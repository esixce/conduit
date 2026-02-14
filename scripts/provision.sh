#!/usr/bin/env bash
# Provision two DigitalOcean droplets for Conduit integration testing.
#
# Prerequisites:
#   1. Install doctl: https://docs.digitalocean.com/reference/doctl/how-to/install/
#   2. Authenticate:  doctl auth init
#   3. Add your SSH key: doctl compute ssh-key list
#      Copy the fingerprint and set SSH_KEY_FINGERPRINT below.
#
# Usage:
#   SSH_KEY_FINGERPRINT=xx:xx:xx:... ./scripts/provision.sh
#
# After running, note the two IP addresses printed at the end.
# Then run: ./scripts/bootstrap.sh <CREATOR_IP> <BUYER_IP>

set -euo pipefail

REGION="${REGION:-nyc1}"
SIZE="${SIZE:-s-1vcpu-1gb}"
IMAGE="${IMAGE:-ubuntu-24-04-x64}"

if [ -z "${SSH_KEY_FINGERPRINT:-}" ]; then
    echo "ERROR: Set SSH_KEY_FINGERPRINT before running."
    echo "  List keys: doctl compute ssh-key list"
    echo "  Usage:     SSH_KEY_FINGERPRINT=xx:xx:xx:... $0"
    exit 1
fi

echo "==> Creating conduit-creator droplet..."
doctl compute droplet create conduit-creator \
    --size "$SIZE" \
    --image "$IMAGE" \
    --region "$REGION" \
    --ssh-keys "$SSH_KEY_FINGERPRINT" \
    --wait \
    --format ID,Name,PublicIPv4 \
    --no-header

echo ""
echo "==> Creating conduit-buyer droplet..."
doctl compute droplet create conduit-buyer \
    --size "$SIZE" \
    --image "$IMAGE" \
    --region "$REGION" \
    --ssh-keys "$SSH_KEY_FINGERPRINT" \
    --wait \
    --format ID,Name,PublicIPv4 \
    --no-header

echo ""
echo "==> Droplets created. IPs:"
doctl compute droplet list --format Name,PublicIPv4 --no-header | grep conduit

echo ""
echo "==> Next step: configure firewall"
echo "    - SSH (22)   : your IP only"
echo "    - LN  (9735) : open between the two droplets"
echo "    - HTTP (8080) : creator only (for file serving)"
echo ""
echo "==> Then run: ./scripts/bootstrap.sh <CREATOR_IP> <BUYER_IP>"
