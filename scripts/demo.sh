#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== 1. Building release binaries ==="
cargo build --release -p zashu-mint -p zashu-wallet -p zashu-auditor

WALLET_FILE=$(mktemp /tmp/zashu_demo_wallet.XXXXXX.json)
MINT_LOG=$(mktemp /tmp/zashu_mint.XXXXXX.log)
rm -f "$WALLET_FILE"

cleanup() {
  if [[ -n "${MINT_PID:-}" ]]; then
    kill "$MINT_PID" 2>/dev/null || true
  fi
  rm -f "$WALLET_FILE" "$MINT_LOG"
}
trap cleanup EXIT

echo "=== 2. Starting unified Mode A + Mode B zashu-mint on 127.0.0.1:18080 ==="
./target/release/zashu-mint --bind 127.0.0.1:18080 >"$MINT_LOG" 2>&1 &
MINT_PID=$!
sleep 1

MINT_URL="http://127.0.0.1:18080"

echo "=== 3. Initializing wallet & minting arbitrary 137 sats (1 shielded note) ==="
./target/release/zashu-wallet --wallet "$WALLET_FILE" --mint "$MINT_URL" init
./target/release/zashu-wallet --wallet "$WALLET_FILE" --mint "$MINT_URL" mint 137
./target/release/zashu-wallet --wallet "$WALLET_FILE" --mint "$MINT_URL" balance

echo "=== 4. Sending 37-sat zashuA bearer token (100 sats shielded change) ==="
TOKEN=$(./target/release/zashu-wallet --wallet "$WALLET_FILE" --mint "$MINT_URL" send-token 37)
echo "Bearer token: ${TOKEN:0:48}..."
./target/release/zashu-wallet --wallet "$WALLET_FILE" --mint "$MINT_URL" receive "$TOKEN"
./target/release/zashu-wallet --wallet "$WALLET_FILE" --mint "$MINT_URL" balance

echo "=== 5. Auditing mint solvency via NUTZ-1 (GET /v1/solvency) ==="
./target/release/zashu-auditor --allow-unverified-utxos verify "$MINT_URL"

echo "=== Demo complete! ==="
