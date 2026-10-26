#!/usr/bin/env bash
# Compline demo: the Annex VII technical file for Zigbee2MQTT 2.14.2 and what changed since 2.13.0,
# built from the evidence bundles in evidence/. No network and no scanners needed (D3, D12).
# Usage: bash demo.sh [OUT_DIR]      default OUT_DIR: demo/
set -euo pipefail
cd "$(dirname "$0")"
OUT=${1:-demo}
mkdir -p "$OUT"
step() { printf '\n== %s\n\n' "$*"; }

step "1. Evidence bundle: SBOM, vulnerabilities, CISA KEV and repository signals, hashed at scan time"
cat evidence/zigbee2mqtt-2.14.2/manifest.json

step "2. Interview: what the public documentation answers, and what is still to ask"
python3 compline.py interview --answers interview/answers-zigbee2mqtt.yaml

step "3. The Annex VII technical file, every claim tied to its evidence or its source"
python3 compline.py annex evidence/zigbee2mqtt-2.14.2 --answers interview/answers-zigbee2mqtt.yaml --out "$OUT/annex-vii-zigbee2mqtt-2.14.2.md"
sed -n '/^### 2(b)/,/^### 2(c)/p' "$OUT/annex-vii-zigbee2mqtt-2.14.2.md" | head -8

step "4. Next release: what changed between 2.13.0 and 2.14.2, the audit trail"
python3 compline.py diff evidence/zigbee2mqtt-2.13.0 evidence/zigbee2mqtt-2.14.2 --answers interview/answers-zigbee2mqtt.yaml --out "$OUT/diff-zigbee2mqtt-2.13.0-2.14.2.md"
grep '^## ' "$OUT/diff-zigbee2mqtt-2.13.0-2.14.2.md"

step "5. Tamper check: drop one finding from the evidence and the file is refused"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp -r evidence/zigbee2mqtt-2.14.2 "$tmp/bundle"
python3 - "$tmp/bundle/grype.json.gz" <<'PY'
import gzip, json, sys
data = json.loads(gzip.decompress(open(sys.argv[1], 'rb').read()))
data['matches'] = data['matches'][1:]
open(sys.argv[1], 'wb').write(gzip.compress(json.dumps(data).encode()))
PY
if python3 compline.py annex "$tmp/bundle" --out "$tmp/annex.md"; then
  echo "FAIL: a changed bundle was accepted"
  exit 1
fi

printf '\nDemo finished in %s s. Files in %s/\n' "$SECONDS" "$OUT"
