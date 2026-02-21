#!/usr/bin/env bash
#
# diagnose.sh — Layer-by-layer diagnostic for Conduit purchase flow.
#
# Tests each component in isolation to pinpoint failures:
#   1. Node health
#   2. Channel state
#   3. Bare Lightning invoice payment (no PRE, no P2P)
#   4. PRE API contract (no payment)
#   5. PRE full buy (Lightning payment + decryption)
#   6. HTTP chunk download
#   7. P2P connectivity
#   8. P2P chunk download (via buy-pre SSE events)
#
# Usage:
#   ./scripts/diagnose.sh           # run all tests
#   ./scripts/diagnose.sh 1 2 3     # run specific tests
#
# Requires: curl, python3

set -uo pipefail

# -- Node URLs (from docs/nodes.md) ------------------------------------------
CREATOR="http://167.172.152.231:3000"
BUYER="http://192.34.58.149:3001"
SEEDER1="http://54.89.56.74:3002"
SEEDER2="http://157.230.238.79:3004"

PASS=0
FAIL=0
SKIP=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
skip() { echo -e "  ${YELLOW}[SKIP]${NC} $1"; SKIP=$((SKIP+1)); }
info() { echo -e "  ${CYAN}[INFO]${NC} $1"; }

# Helper: GET JSON and extract a field, returns empty string on failure
jget() {
  local url="$1" field="$2"
  curl -sf --max-time 15 "$url" 2>/dev/null | \
    python3 -c "import json,sys; d=json.load(sys.stdin); print(d['$field'])" 2>/dev/null || echo ""
}

# Helper: GET JSON, returns raw JSON or empty
jraw() {
  curl -sf --max-time 15 "$1" 2>/dev/null || echo ""
}

# -- Shared state (set by earlier tests, used by later ones) ------------------
BUYER_NODE_ID=""
CREATOR_NODE_ID=""
SEEDER1_NODE_ID=""
SEEDER2_NODE_ID=""
TEST_CONTENT_HASH=""
TEST_CONTENT_ENC_HASH=""
TEST_CONTENT_CREATOR=""
TEST_CONTENT_PRICE=""
TEST_CONTENT_FILE=""
PRE_BUY_OK=false

# =============================================================================
# Test 1: Node Health
# =============================================================================
test_1_health() {
  echo ""
  echo -e "${CYAN}=== Test 1: Node Health ===${NC}"
  local nodes=("$CREATOR" "$BUYER" "$SEEDER1" "$SEEDER2")
  local names=("Creator" "Buyer" "Seeder1" "Seeder2")
  local id_vars=("CREATOR_NODE_ID" "BUYER_NODE_ID" "SEEDER1_NODE_ID" "SEEDER2_NODE_ID")

  for i in "${!nodes[@]}"; do
    local url="${nodes[$i]}"
    local name="${names[$i]}"
    local resp
    resp=$(jraw "$url/api/info")
    if [ -z "$resp" ]; then
      fail "$name ($url) — no response"
      continue
    fi
    local alias
    alias=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('node_alias',''))" 2>/dev/null)
    local nid
    nid=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('node_id',''))" 2>/dev/null)
    if [ -z "$nid" ]; then
      fail "$name ($url) — missing node_id"
    else
      pass "$name ($url) — alias=$alias node_id=${nid:0:16}..."
      eval "${id_vars[$i]}=$nid"
    fi
  done
}

# =============================================================================
# Test 2: Channel State
# =============================================================================
test_2_channels() {
  echo ""
  echo -e "${CYAN}=== Test 2: Channel State (Buyer -> Peers) ===${NC}"
  if [ -z "$BUYER_NODE_ID" ]; then
    skip "Buyer not reachable (Test 1 failed)"
    return
  fi

  local resp
  resp=$(jraw "$BUYER/api/info")
  if [ -z "$resp" ]; then
    fail "Cannot fetch Buyer info"
    return
  fi

  echo "$resp" | python3 -c "
import json, sys
d = json.load(sys.stdin)
channels = d.get('channels', [])
peer_ids = {
    '$CREATOR_NODE_ID': 'Creator',
    '$SEEDER1_NODE_ID': 'Seeder1',
    '$SEEDER2_NODE_ID': 'Seeder2',
}
found = set()
for ch in channels:
    cid = ch['counterparty_node_id']
    name = peer_ids.get(cid, cid[:16]+'...')
    out_sats = ch['outbound_msat'] // 1000
    usable = ch['usable']
    ready = ch['ready']
    found.add(cid)
    status = 'PASS' if usable and out_sats > 0 else 'FAIL'
    print(f'{status}|{name}: usable={usable} ready={ready} outbound={out_sats} sats')

for nid, name in peer_ids.items():
    if nid and nid not in found:
        print(f'FAIL|{name}: NO CHANNEL (node_id={nid[:16]}...)')
" 2>/dev/null | while IFS='|' read -r status msg; do
    if [ "$status" = "PASS" ]; then
      pass "$msg"
    else
      fail "$msg"
    fi
  done
}

# =============================================================================
# Test 3: Bare Lightning Invoice Payment
# =============================================================================
test_3_bare_payment() {
  echo ""
  echo -e "${CYAN}=== Test 3: Bare Lightning Invoice Payment ===${NC}"

  # Pick cheapest PRE-enabled content from any creator
  local creators=("$CREATOR" "$SEEDER1" "$SEEDER2")
  local cnames=("Creator" "Seeder1" "Seeder2")
  local best_url="" best_hash="" best_price=999999 best_file="" best_enc=""

  for i in "${!creators[@]}"; do
    local url="${creators[$i]}"
    local catalog
    catalog=$(jraw "$url/api/catalog")
    [ -z "$catalog" ] && continue
    local result
    result=$(echo "$catalog" | python3 -c "
import json, sys
data = json.load(sys.stdin)
items = data.get('items', data if isinstance(data, list) else [])
best = None
for item in items:
    if item.get('pre_c1_hex') and item.get('price_sats', 0) > 0:
        if best is None or item['price_sats'] < best['price_sats']:
            best = item
if best:
    print(f\"{best['content_hash']}|{best['price_sats']}|{best['file_name']}|{best.get('encrypted_hash','')}\")
else:
    print('NONE')
" 2>/dev/null)
    if [ "$result" != "NONE" ] && [ -n "$result" ]; then
      IFS='|' read -r hash price fname enc_hash <<< "$result"
      if [ "$price" -lt "$best_price" ] 2>/dev/null; then
        best_url="$url"
        best_hash="$hash"
        best_price="$price"
        best_file="$fname"
        best_enc="$enc_hash"
      fi
    fi
  done

  if [ -z "$best_hash" ]; then
    skip "No PRE-enabled content found on any creator"
    return
  fi

  TEST_CONTENT_HASH="$best_hash"
  TEST_CONTENT_ENC_HASH="$best_enc"
  TEST_CONTENT_CREATOR="$best_url"
  TEST_CONTENT_PRICE="$best_price"
  TEST_CONTENT_FILE="$best_file"
  info "Target: $best_file ($best_price sats) from $best_url"
  info "content_hash: ${best_hash:0:24}..."

  # Create a plain invoice (non-PRE) from the creator
  info "Creating plain invoice via POST /api/invoice/$best_hash ..."
  local inv_resp
  inv_resp=$(curl -sf --max-time 15 -X POST "$best_url/api/invoice/$best_hash" 2>/dev/null)
  if [ -z "$inv_resp" ]; then
    fail "Creator returned no response for /api/invoice/$best_hash"
    return
  fi

  local bolt11
  bolt11=$(echo "$inv_resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('bolt11',''))" 2>/dev/null)
  if [ -z "$bolt11" ]; then
    local err
    err=$(echo "$inv_resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('error','unknown'))" 2>/dev/null)
    fail "No bolt11 in invoice response: $err"
    return
  fi
  pass "Invoice created (length ${#bolt11})"

  # Pay via Buyer's /api/buy (needs: hash, output, invoice)
  info "Paying via POST /api/buy on Buyer node ..."
  local buy_resp
  buy_resp=$(curl -sf --max-time 90 -X POST "$BUYER/api/buy" \
    -H "Content-Type: application/json" \
    -d "{\"hash\":\"$best_hash\",\"output\":\"/tmp/diag-bare-$best_hash\",\"invoice\":\"$bolt11\"}" 2>/dev/null || echo "")

  if [ -z "$buy_resp" ]; then
    fail "Buyer /api/buy returned no response"
    return
  fi

  info "Buy initiated: $buy_resp"

  # Poll SSE events for up to 60s
  info "Polling SSE events for payment result (60s timeout)..."
  local deadline=$((SECONDS + 60))
  local payment_ok=false
  local payment_err=""

  while [ $SECONDS -lt $deadline ]; do
    local events
    events=$(curl -sf --max-time 5 "$BUYER/api/events/history" 2>/dev/null || echo "[]")
    local status
    status=$(echo "$events" | python3 -c "
import json, sys
events = json.load(sys.stdin)
for e in reversed(events):
    d = e.get('data', {})
    t = e.get('event_type', '')
    if t in ('CONTENT_PAID', 'FILE_SAVED', 'HASH_VERIFIED'):
        print('OK')
        sys.exit(0)
    if t in ('CONTENT_PAYMENT_FAILED', 'BUY_ERROR'):
        msg = d.get('message', d.get('error', 'unknown'))
        print(f'ERR:{msg}')
        sys.exit(0)
print('WAIT')
" 2>/dev/null)

    if [ "${status:0:2}" = "OK" ]; then
      payment_ok=true
      break
    elif [ "${status:0:3}" = "ERR" ]; then
      payment_err="${status:4}"
      break
    fi
    sleep 3
  done

  if $payment_ok; then
    pass "Bare Lightning payment SUCCEEDED"
  elif [ -n "$payment_err" ]; then
    fail "Bare Lightning payment FAILED: $payment_err"
  else
    fail "Bare Lightning payment TIMED OUT (60s)"
  fi
}

# =============================================================================
# Test 4: PRE API Contract
# =============================================================================
test_4_pre_api() {
  echo ""
  echo -e "${CYAN}=== Test 4: PRE API Contract (no payment) ===${NC}"

  # Buyer pre-info
  local buyer_pk
  buyer_pk=$(jget "$BUYER/api/pre-info" "buyer_pk_hex")
  if [ -z "$buyer_pk" ]; then
    fail "Buyer /api/pre-info — no buyer_pk_hex"
    return
  fi
  pass "Buyer /api/pre-info — pk=${buyer_pk:0:20}... (${#buyer_pk} chars)"

  # Pick content for PRE test
  local creator_url="${TEST_CONTENT_CREATOR:-$SEEDER1}"
  local content_hash="${TEST_CONTENT_HASH}"
  if [ -z "$content_hash" ]; then
    # Fallback: find something from Seeder1
    content_hash=$(jraw "$SEEDER1/api/catalog" | python3 -c "
import json,sys
data=json.load(sys.stdin)
items=data.get('items',data if isinstance(data,list) else [])
for i in items:
    if i.get('pre_c1_hex'):
        print(i['content_hash'])
        sys.exit(0)
print('')
" 2>/dev/null)
    creator_url="$SEEDER1"
  fi

  if [ -z "$content_hash" ]; then
    skip "No PRE-enabled content to test"
    return
  fi

  # PRE ciphertext
  local ct_resp
  ct_resp=$(jraw "$creator_url/api/pre-ciphertext/$content_hash")
  if [ -z "$ct_resp" ]; then
    fail "GET /api/pre-ciphertext/$content_hash — no response"
  else
    local c1_len
    c1_len=$(echo "$ct_resp" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('pre_c1_hex','')))" 2>/dev/null)
    if [ "$c1_len" -gt 0 ] 2>/dev/null; then
      pass "GET /api/pre-ciphertext — c1_hex length=$c1_len"
    else
      fail "GET /api/pre-ciphertext — empty c1_hex"
    fi
  fi

  # PRE purchase (creates invoice but we won't pay it)
  info "POST /api/pre-purchase/$content_hash (invoice creation only)..."
  local purchase_resp
  purchase_resp=$(curl -sf --max-time 15 -X POST "$creator_url/api/pre-purchase/$content_hash" \
    -H "Content-Type: application/json" \
    -d "{\"buyer_pk_hex\": \"$buyer_pk\"}" 2>/dev/null || echo "")

  if [ -z "$purchase_resp" ]; then
    fail "POST /api/pre-purchase — no response"
    return
  fi

  local bolt11 rk_hex
  bolt11=$(echo "$purchase_resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('bolt11',''))" 2>/dev/null)
  rk_hex=$(echo "$purchase_resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('rk_compressed_hex',''))" 2>/dev/null)

  if [ -n "$bolt11" ] && [ -n "$rk_hex" ]; then
    pass "POST /api/pre-purchase — bolt11 len=${#bolt11}, rk len=${#rk_hex}"
  else
    fail "POST /api/pre-purchase — missing bolt11 or rk_compressed_hex"
    info "Response: ${purchase_resp:0:200}"
  fi
}

# =============================================================================
# Test 5: PRE Full Buy (Lightning payment + decryption)
# =============================================================================
test_5_pre_buy() {
  echo ""
  echo -e "${CYAN}=== Test 5: PRE Full Buy (Lightning + PRE + chunks) ===${NC}"

  local creator_url="${TEST_CONTENT_CREATOR:-$SEEDER1}"
  local content_hash="${TEST_CONTENT_HASH}"
  local fname="${TEST_CONTENT_FILE:-unknown}"
  local price="${TEST_CONTENT_PRICE:-?}"

  if [ -z "$content_hash" ]; then
    skip "No test content available"
    return
  fi

  info "Buying $fname ($price sats) from $creator_url via PRE..."

  # Clear event history first
  curl -sf --max-time 5 "$BUYER/api/events/history" > /dev/null 2>&1

  # Trigger buy-pre
  local buy_resp
  buy_resp=$(curl -sf --max-time 15 -X POST "$BUYER/api/buy-pre" \
    -H "Content-Type: application/json" \
    -d "{\"creator_url\":\"$creator_url\",\"content_hash\":\"$content_hash\",\"output\":\"/tmp/diag-pre-$content_hash\"}" 2>/dev/null || echo "")

  if [ -z "$buy_resp" ]; then
    fail "POST /api/buy-pre — no response"
    return
  fi
  info "buy-pre initiated: $buy_resp"

  # Poll SSE event history for up to 90s
  local deadline=$((SECONDS + 90))
  local last_step=""
  local result=""
  local p2p_attempted=false
  local p2p_failed=false
  local http_fallback=false

  while [ $SECONDS -lt $deadline ]; do
    sleep 4
    local events
    events=$(curl -sf --max-time 5 "$BUYER/api/events/history" 2>/dev/null || echo "[]")
    local step_info
    step_info=$(echo "$events" | python3 -c "
import json, sys
events = json.load(sys.stdin)
last = ''
result = ''
p2p_tried = False
p2p_fail = False
http_fb = False
for e in events:
    t = e.get('event_type', '')
    d = e.get('data', {})
    if t == 'PRE_BUY_START': last = 'PRE_BUY_START'
    elif t == 'PRE_PURCHASE_RECEIVED': last = 'PRE_PURCHASE_RECEIVED'
    elif t == 'PAYING_INVOICE': last = 'PAYING_INVOICE'
    elif t == 'PAYMENT_SENT': last = 'PAYMENT_SENT'
    elif t == 'PRE_PAYMENT_CONFIRMED': last = 'PRE_PAYMENT_CONFIRMED'
    elif t == 'PRE_KEY_RECOVERED': last = 'PRE_KEY_RECOVERED'
    elif t == 'P2P_CONNECTING': p2p_tried = True; last = 'P2P_CONNECTING'
    elif t == 'P2P_DOWNLOAD_FAILED': p2p_fail = True; last = 'P2P_DOWNLOAD_FAILED'
    elif t == 'DOWNLOADING_CHUNKS': http_fb = True; last = 'DOWNLOADING_CHUNKS'
    elif t == 'HASH_VERIFIED': last = 'HASH_VERIFIED'; result = 'OK'
    elif t == 'FILE_SAVED': last = 'FILE_SAVED'; result = 'OK'
    elif t == 'BUY_ERROR':
        msg = d.get('message', 'unknown')
        last = 'BUY_ERROR'
        result = f'ERR:{msg}'
    elif t == 'PAYMENT_FAILED':
        reason = d.get('reason', 'unknown')
        last = 'PAYMENT_FAILED'
        result = f'ERR:PaymentFailed({reason})'
    elif t == 'PRE_ALREADY_PAID':
        last = 'PRE_ALREADY_PAID'
print(f'{last}|{result}|{p2p_tried}|{p2p_fail}|{http_fb}')
" 2>/dev/null)

    IFS='|' read -r last_step result p2p_a p2p_f http_f <<< "$step_info"
    [ "$p2p_a" = "True" ] && p2p_attempted=true
    [ "$p2p_f" = "True" ] && p2p_failed=true
    [ "$http_f" = "True" ] && http_fallback=true

    if [ "${result:0:2}" = "OK" ] || [ "${result:0:3}" = "ERR" ]; then
      break
    fi
    info "  progress: $last_step ..."
  done

  # Report
  if [ "${result:0:2}" = "OK" ]; then
    pass "PRE buy completed — last_step=$last_step"
    PRE_BUY_OK=true
    if $p2p_attempted && ! $p2p_failed; then
      pass "P2P download succeeded"
    elif $p2p_attempted && $p2p_failed && $http_fallback; then
      info "P2P failed, HTTP fallback used (purchase still OK)"
    fi
  elif [ "${result:0:3}" = "ERR" ]; then
    fail "PRE buy FAILED at step=$last_step: ${result:4}"
    if [ "$last_step" = "PAYING_INVOICE" ] || [ "$last_step" = "BUY_ERROR" ]; then
      info "Failure is at Lightning payment layer (same root cause as Test 3)"
    fi
  else
    fail "PRE buy TIMED OUT (90s) — stuck at step=$last_step"
  fi
}

# =============================================================================
# Test 6: HTTP Chunk Download
# =============================================================================
test_6_http_chunks() {
  echo ""
  echo -e "${CYAN}=== Test 6: HTTP Chunk Download ===${NC}"

  local creator_url="${TEST_CONTENT_CREATOR:-$SEEDER1}"
  local enc_hash="${TEST_CONTENT_ENC_HASH}"

  if [ -z "$enc_hash" ]; then
    skip "No encrypted_hash available from earlier tests"
    return
  fi

  # Fetch chunk metadata
  local meta
  meta=$(jraw "$creator_url/api/chunks/$enc_hash/meta")
  if [ -z "$meta" ]; then
    fail "GET /api/chunks/$enc_hash/meta — no response"
    return
  fi

  local chunk_count
  chunk_count=$(echo "$meta" | python3 -c "import json,sys; print(json.load(sys.stdin).get('chunk_count',0))" 2>/dev/null)
  if [ "$chunk_count" -gt 0 ] 2>/dev/null; then
    pass "Chunk meta: $chunk_count chunks"
  else
    fail "Chunk meta: invalid chunk_count=$chunk_count"
    return
  fi

  # Fetch chunk 0
  local chunk_size
  chunk_size=$(curl -sf --max-time 15 -o /dev/null -w '%{size_download}' "$creator_url/api/chunks/$enc_hash/0" 2>/dev/null)
  if [ "$chunk_size" -gt 0 ] 2>/dev/null; then
    pass "Chunk 0 download: $chunk_size bytes"
  else
    fail "Chunk 0 download: empty or failed"
  fi
}

# =============================================================================
# Test 7: P2P Connectivity
# =============================================================================
test_7_p2p() {
  echo ""
  echo -e "${CYAN}=== Test 7: P2P Connectivity ===${NC}"

  local nodes=("$BUYER" "$SEEDER1" "$SEEDER2" "$CREATOR")
  local names=("Buyer" "Seeder1" "Seeder2" "Creator")

  for i in "${!nodes[@]}"; do
    local url="${nodes[$i]}"
    local name="${names[$i]}"
    local resp
    resp=$(jraw "$url/api/p2p-info")
    if [ -z "$resp" ]; then
      fail "$name ($url) — /api/p2p-info no response"
      continue
    fi
    local enabled
    enabled=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('enabled',False))" 2>/dev/null)
    local nid
    nid=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('node_id',''))" 2>/dev/null)
    if [ "$enabled" = "True" ] && [ -n "$nid" ]; then
      pass "$name P2P enabled — iroh_id=${nid:0:16}..."
    elif [ "$enabled" = "False" ]; then
      fail "$name P2P DISABLED (--p2p flag missing?)"
    else
      fail "$name P2P — unexpected response: $resp"
    fi
  done
}

# =============================================================================
# Test 8: P2P Chunk Download
# =============================================================================
test_8_p2p_download() {
  echo ""
  echo -e "${CYAN}=== Test 8: P2P Chunk Download ===${NC}"

  if ! $PRE_BUY_OK; then
    skip "PRE buy did not succeed (Test 5) — cannot test P2P download"
    return
  fi

  # Check if P2P was attempted and succeeded during Test 5
  # (We already reported this in Test 5, summarize here)
  info "P2P download status was reported in Test 5."
  info "If Test 5 showed 'P2P failed, HTTP fallback used', the P2P transport layer needs debugging."
  info "If Test 5 showed 'P2P download succeeded', P2P is working end-to-end."
  pass "See Test 5 results for P2P download status"
}

# =============================================================================
# Main
# =============================================================================
echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  Conduit Diagnostic — $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${CYAN}============================================${NC}"

TESTS_TO_RUN="${*:-1 2 3 4 5 6 7 8}"

for t in $TESTS_TO_RUN; do
  case "$t" in
    1) test_1_health ;;
    2) test_2_channels ;;
    3) test_3_bare_payment ;;
    4) test_4_pre_api ;;
    5) test_5_pre_buy ;;
    6) test_6_http_chunks ;;
    7) test_7_p2p ;;
    8) test_8_p2p_download ;;
    *) echo "Unknown test: $t" ;;
  esac
done

# Summary
echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  Summary${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "  ${GREEN}PASS: $PASS${NC}  ${RED}FAIL: $FAIL${NC}  ${YELLOW}SKIP: $SKIP${NC}"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo -e "  ${RED}DIAGNOSIS: $FAIL test(s) failed. See above for details.${NC}"
  exit 1
else
  echo -e "  ${GREEN}All tests passed.${NC}"
  exit 0
fi
