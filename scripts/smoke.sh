#!/usr/bin/env bash
# Quick health check against a running VChain instance.
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:12000}"

echo "health:"
curl -fsS "$BASE/api/health" | python -m json.tool

echo
echo "chain:"
curl -fsS "$BASE/api/chain/verify" | python -m json.tool

echo
echo "audit:"
curl -fsS -X POST "$BASE/api/audit" | python -m json.tool | head -30

echo
echo "snapshot summary:"
curl -fsS "$BASE/api/snapshot" | python -c 'import json,sys
s=json.load(sys.stdin)
st=s["stats"]
print("  readings anchored : %s" % st["readings_anchored"])
print("  chain height      : %s" % st["chain_height"])
print("  chain ok          : %s" % st["chain_ok"])
print("  p95 latency       : %s ms" % st["latency"]["p95_ms"])
print("  alerts            : %s (%s excursions)" % (st["alerts_total"], st["excursions"]))
print("  nodes online      : %s/%s" % (s["network"]["nodes_online"], s["network"]["nodes_total"]))'
