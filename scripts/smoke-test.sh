#!/usr/bin/env sh
set -eu

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
PANEL_USERNAME="${PANEL_USERNAME:-admin}"
PANEL_PASSWORD="${PANEL_PASSWORD:?Set PANEL_PASSWORD before running smoke test}"
COOKIE_JAR="${COOKIE_JAR:-/tmp/network-panel-smoke-cookies.txt}"

rm -f "$COOKIE_JAR"

login() {
  printf 'Signing in as %s ... ' "$PANEL_USERNAME"
  payload="$(printf '{"username":"%s","password":"%s"}' "$PANEL_USERNAME" "$PANEL_PASSWORD")"
  if response="$(curl -fsS --max-time 5 -c "$COOKIE_JAR" -H 'Content-Type: application/json' -d "$payload" "${BASE_URL}/api/auth/login" 2>&1)"; then
    printf 'ok\n'
  else
    printf 'failed\n%s\n' "$response" >&2
    return 1
  fi
}

check() {
  path="$1"
  url="${BASE_URL}${path}"
  printf 'Checking %s ... ' "$url"
  if response="$(curl -fsS --max-time 5 -b "$COOKIE_JAR" "$url" 2>&1)"; then
    bytes="$(printf '%s' "$response" | wc -c | tr -d ' ')"
    printf 'ok (%s bytes)\n' "$bytes"
  else
    printf 'failed\n%s\n' "$response" >&2
    return 1
  fi
}

check /api/health
login
check /api/auth/status
check /api/overview
check /api/system/stats
check /api/services
check /api/filesystem
check /api/device-io
check /api/wifi/status

printf 'Smoke test complete.\n'
