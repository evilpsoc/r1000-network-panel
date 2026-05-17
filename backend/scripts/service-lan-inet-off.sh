#!/usr/bin/env bash
set -euo pipefail

detect_interface() {
  local detected
  detected="$(nft list tables 2>/dev/null | awk '/table ip nm-shared-/{sub(/^table ip nm-shared-/, "", $0); print $0; exit}')"
  if [[ -n "$detected" ]]; then
    printf '%s\n' "$detected"
    return
  fi
  printf '%s\n' "enx2cf7f1232c1a"
}

IFACE="${SERVICE_LAN_INTERFACE:-}"
IFACE="${IFACE:-$(detect_interface)}"
IPV6_GATEWAY="${SERVICE_LAN_IPV6_GATEWAY:-}"
IPV6_PREFIX="${SERVICE_LAN_IPV6_PREFIX:-}"
DNSMASQ_SHARED_DIR="/etc/NetworkManager/dnsmasq-shared.d"
DNSMASQ_IPV6_CONF="$DNSMASQ_SHARED_DIR/99-service-lan-ipv6.conf"
RA_PID="/run/service-lan-ra.pid"

prefix_length() {
  printf '%s\n' "${1#*/}"
}

stop_radvd() {
  if [[ -f "$RA_PID" ]]; then
    kill "$(cat "$RA_PID")" >/dev/null 2>&1 || true
  fi
  rm -f "$RA_PID"
}

reload_dnsmasq() {
  local pid
  pid="$(pgrep -f "nm-dnsmasq-${IFACE}" | head -n1 || true)"
  if [[ -n "$pid" ]]; then
    kill -HUP "$pid" >/dev/null 2>&1 || true
  fi
}

nft list table inet service_lan_block >/dev/null 2>&1 && nft delete table inet service_lan_block || true
nft list table inet service_lan >/dev/null 2>&1 && nft delete table inet service_lan || true
nft list table ip service_lan_nat >/dev/null 2>&1 && nft delete table ip service_lan_nat || true
nft list table ip service_lan_nat_v4 >/dev/null 2>&1 && nft delete table ip service_lan_nat_v4 || true
nft list table ip6 service_lan_nat_v6 >/dev/null 2>&1 && nft delete table ip6 service_lan_nat_v6 || true
stop_radvd
rm -f "$DNSMASQ_IPV6_CONF"
reload_dnsmasq
ip -6 addr del "${IPV6_GATEWAY}/$(prefix_length "$IPV6_PREFIX")" dev "$IFACE" >/dev/null 2>&1 || true

nft add table inet service_lan_block
nft 'add chain inet service_lan_block forward { type filter hook forward priority -5; policy accept; }'
nft add rule inet service_lan_block forward iifname "$IFACE" drop
nft add rule inet service_lan_block forward oifname "$IFACE" drop
