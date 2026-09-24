#!/usr/bin/env bash
# White-box coverage for all three code bases. Reports land in coverage/:
#   coverage/gateway.html        line-by-line Go coverage (open in a browser)
#   coverage/control-plane/      line-by-line Python coverage (index.html)
#   coverage/summary.txt         per-package percentages for all three
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/coverage"
rm -rf "$out" && mkdir -p "$out"

echo "== Go gateway"
(
  cd "$root/gateway"
  go test -coverprofile="$out/gateway.out" ./... >/dev/null
  go tool cover -html="$out/gateway.out" -o "$out/gateway.html"
  {
    echo "== Go gateway (statements)"
    go test -cover ./... | grep -v "no test files" \
      | sed -E 's#^(ok)?[[:space:]]*github.com/[^/]+/[^/]+/##; s#[[:space:]].*coverage:[[:space:]]*#  #; s#[[:space:]]*of statements##' \
      | awk '{printf "%-24s %s\n", $1, $2}'
    go tool cover -func="$out/gateway.out" | tail -1 | sed -E 's/[[:space:]]+/ /g'
  } >>"$out/summary.txt"
)

echo "== Python control plane"
(
  cd "$root/control-plane"
  PYTHONPATH=. .venv/bin/python -m pytest -q --cov=iasg --cov-report=html:"$out/control-plane" \
    --cov-report=term >"$out/control-plane.txt"
  { echo; echo "== Python control plane (statements)"; grep -E "^(iasg/|TOTAL)" "$out/control-plane.txt"; } >>"$out/summary.txt"
)

echo "== Dashboard (logic modules with tests)"
(
  cd "$root/gateway-dashboard"
  # The tests import only Node built-ins, so no npm install is needed; without a
  # local Node, the stack's own image runs them.
  cmd='node --test --experimental-test-coverage tests/*.test.mjs'
  if command -v node >/dev/null; then
    sh -c "$cmd" >"$out/dashboard.txt" 2>&1
  else
    docker run --rm -v "$PWD:/app:ro" -w /app node:22-alpine sh -c "$cmd" >"$out/dashboard.txt" 2>&1
  fi
  { echo; echo "== Dashboard (lines, tested modules only)"; grep -E "^# +[a-z].*\|" "$out/dashboard.txt" || true; } >>"$out/summary.txt"
)

cat "$out/summary.txt"
echo
echo "Open $out/gateway.html and $out/control-plane/index.html"
