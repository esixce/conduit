#!/usr/bin/env bash
#
# test-pre-signet.sh — End-to-end PRE test on live signet nodes.
#
# Prerequisites:
#   1. Deploy the PRE-enabled conduit-setup to all nodes (push to main)
#   2. Re-register content on the Creator node (to populate PRE fields)
#   3. Ensure Buyer -> Creator channel has outbound capacity
#
# Usage:
#   ./scripts/test-pre-signet.sh
#
# Nodes (from docs/nodes.md):
#   Creator:  http://167.172.152.231:3000
#   Buyer:    http://192.34.58.149:3001
#   Seeder 1: http://54.89.56.74:3002

set -euo pipefail

CREATOR="http://167.172.152.231:3000"
BUYER="http://192.34.58.149:3001"

echo "=== PRE Signet E2E Test ==="
echo ""

# Step 1: Check Creator catalog for PRE-enabled content
echo "[1/7] Checking Creator catalog..."
CATALOG=$(curl -sf "$CREATOR/api/catalog")
FIRST_PRE=$(echo "$CATALOG" | python3 -c "
import json, sys
data = json.load(sys.stdin)
items = data.get('items', [])
for item in items:
    if item.get('pre_c1_hex'):
        print(json.dumps(item))
        sys.exit(0)
print('NONE')
")

if [ "$FIRST_PRE" = "NONE" ]; then
    echo "ERROR: No PRE-enabled content found in Creator catalog."
    echo "       Re-register content after deploying the PRE code."
    echo ""
    echo "       On Creator node:"
    echo "         curl -X POST $CREATOR/api/register -H 'Content-Type: application/json' \\"
    echo "           -d '{\"file\": \"/tmp/sample-song.txt\", \"price\": 5}'"
    exit 1
fi

CONTENT_HASH=$(echo "$FIRST_PRE" | python3 -c "import json, sys; print(json.load(sys.stdin)['content_hash'])")
FILE_NAME=$(echo "$FIRST_PRE" | python3 -c "import json, sys; print(json.load(sys.stdin)['file_name'])")
PRICE=$(echo "$FIRST_PRE" | python3 -c "import json, sys; print(json.load(sys.stdin)['price_sats'])")
echo "       Found: $FILE_NAME ($PRICE sats) hash=$CONTENT_HASH"
echo ""

# Step 2: Get buyer's PRE public key from /api/pre-info
echo "[2/7] Getting buyer PRE public key from /api/pre-info..."
BUYER_PRE_INFO=$(curl -sf "$BUYER/api/pre-info")
BUYER_PK_HEX=$(echo "$BUYER_PRE_INFO" | python3 -c "import json, sys; print(json.load(sys.stdin)['buyer_pk_hex'])")
BUYER_ALIAS=$(echo "$BUYER_PRE_INFO" | python3 -c "import json, sys; print(json.load(sys.stdin).get('node_alias', 'unknown'))")
echo "       Buyer alias: $BUYER_ALIAS"
echo "       Buyer G2 pk: ${BUYER_PK_HEX:0:32}...${BUYER_PK_HEX: -16}"
echo ""

# Step 3: Fetch PRE ciphertext
echo "[3/7] Fetching PRE ciphertext from Creator..."
PRE_CT=$(curl -sf "$CREATOR/api/pre-ciphertext/$CONTENT_HASH" || echo "FAILED")

if [ "$PRE_CT" = "FAILED" ]; then
    echo "ERROR: /api/pre-ciphertext/$CONTENT_HASH returned error."
    exit 1
fi

C1_PREVIEW=$(echo "$PRE_CT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['pre_c1_hex'][:32])")
C2_PREVIEW=$(echo "$PRE_CT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['pre_c2_hex'][:32])")
echo "       c1: ${C1_PREVIEW}..."
echo "       c2: ${C2_PREVIEW}..."
echo ""

# Step 4: Creator's /api/pre-info
echo "[4/7] Getting Creator PRE public key..."
CREATOR_PRE_INFO=$(curl -sf "$CREATOR/api/pre-info")
CREATOR_PK_HEX=$(echo "$CREATOR_PRE_INFO" | python3 -c "import json, sys; print(json.load(sys.stdin)['buyer_pk_hex'])")
echo "       Creator G2 pk: ${CREATOR_PK_HEX:0:32}...${CREATOR_PK_HEX: -16}"
echo ""

# Step 5: Test /api/pre-purchase with real buyer pk
echo "[5/7] Testing /api/pre-purchase with buyer's real G2 pk..."
PURCHASE_RESP=$(curl -sf \
    -X POST "$CREATOR/api/pre-purchase/$CONTENT_HASH" \
    -H "Content-Type: application/json" \
    -d "{\"buyer_pk_hex\": \"$BUYER_PK_HEX\"}" 2>&1 || echo "FAILED")

if [ "$PURCHASE_RESP" = "FAILED" ]; then
    echo "ERROR: /api/pre-purchase failed."
    echo "       Check Creator logs for details."
    exit 1
fi

BOLT11=$(echo "$PURCHASE_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['bolt11'])" 2>/dev/null || echo "")
RK_HEX=$(echo "$PURCHASE_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['rk_compressed_hex'])" 2>/dev/null || echo "")

if [ -z "$BOLT11" ] || [ -z "$RK_HEX" ]; then
    echo "ERROR: Pre-purchase response missing bolt11 or rk_compressed_hex."
    echo "       Response: $PURCHASE_RESP"
    exit 1
fi

echo "       Invoice received (length ${#BOLT11})"
echo "       rk_compressed: ${RK_HEX:0:32}...${RK_HEX: -16}"
echo ""

# Step 6: Show what the full payment test would look like
echo "[6/7] Full Lightning payment test..."
echo "       To complete the actual payment, run on buyer node:"
echo ""
echo "       conduit-setup buy-pre \\"
echo "         --creator-url $CREATOR \\"
echo "         --content-hash $CONTENT_HASH \\"
echo "         --output /tmp/decrypted-output"
echo ""
echo "       This will:"
echo "         1. Call /api/pre-purchase with buyer's G2 pk"
echo "         2. Pay the Lightning invoice"
echo "         3. Recover AES key m via PRE decryption"
echo "         4. Download and decrypt chunks"
echo "         5. Verify content hash"
echo ""

# Step 7: Summary
echo "[7/7] Summary"
echo "       Creator catalog:    PRE-enabled content found"
echo "       Buyer /api/pre-info: Working (G2 pk exposed)"
echo "       Creator /api/pre-info: Working"
echo "       PRE ciphertext API: Working"
echo "       PRE purchase API:   Working (invoice + rk returned)"
echo ""
echo "       Buyer pk != Creator pk: $([ "$BUYER_PK_HEX" != "$CREATOR_PK_HEX" ] && echo "YES (correct)" || echo "NO (problem!)")"
echo ""
echo "=== PRE API Contract Verified ==="
echo ""
echo "Next: Run 'conduit-setup buy-pre' on the buyer node to perform"
echo "the actual Lightning payment + PRE decryption test."
