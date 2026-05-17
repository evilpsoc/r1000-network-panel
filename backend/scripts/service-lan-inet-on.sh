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
IPV4_SUBNET="${SERVICE_LAN_IPV4_SUBNET:-}"
IPV6_GATEWAY="${SERVICE_LAN_IPV6_GATEWAY:-}"
IPV6_PREFIX="${SERVICE_LAN_IPV6_PREFIX:-}"
ENABLE_IPV4="${SERVICE_LAN_ENABLE_IPV4:-false}"
ENABLE_IPV6="${SERVICE_LAN_ENABLE_IPV6:-false}"
DNSMASQ_SHARED_DIR="/etc/NetworkManager/dnsmasq-shared.d"
DNSMASQ_IPV6_CONF="$DNSMASQ_SHARED_DIR/99-service-lan-ipv6.conf"
RA_PID="/run/service-lan-ra.pid"

is_enabled() {
  case "${1,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

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

nft list table inet service_lan >/dev/null 2>&1 && nft delete table inet service_lan || true
nft list table inet service_lan_block >/dev/null 2>&1 && nft delete table inet service_lan_block || true
nft list table ip service_lan_nat >/dev/null 2>&1 && nft delete table ip service_lan_nat || true
nft list table ip service_lan_nat_v4 >/dev/null 2>&1 && nft delete table ip service_lan_nat_v4 || true
nft list table ip6 service_lan_nat_v6 >/dev/null 2>&1 && nft delete table ip6 service_lan_nat_v6 || true
stop_radvd

nft add table inet service_lan
nft 'add chain inet service_lan forward { type filter hook forward priority 10; policy accept; }'
nft add rule inet service_lan forward iifname "$IFACE" counter accept
nft add rule inet service_lan forward oifname "$IFACE" ct state established,related counter accept

if is_enabled "$ENABLE_IPV4"; then
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  nft add table ip service_lan_nat_v4
  nft 'add chain ip service_lan_nat_v4 postrouting { type nat hook postrouting priority 110; policy accept; }'
  nft add rule ip service_lan_nat_v4 postrouting oifname != "$IFACE" ip saddr "$IPV4_SUBNET" counter masquerade
fi

if is_enabled "$ENABLE_IPV6"; then
  sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
  sysctl -w "net.ipv6.conf.${IFACE}.disable_ipv6=0" >/dev/null 2>&1 || true
  ip link set dev "$IFACE" addrgenmode eui64 >/dev/null 2>&1 || true
  ip link set dev "$IFACE" up >/dev/null 2>&1 || true
  ip -6 addr replace "${IPV6_GATEWAY}/$(prefix_length "$IPV6_PREFIX")" dev "$IFACE" >/dev/null 2>&1 || true
  nft add table ip6 service_lan_nat_v6
  nft 'add chain ip6 service_lan_nat_v6 postrouting { type nat hook postrouting priority 110; policy accept; }'
  nft add rule ip6 service_lan_nat_v6 postrouting oifname != "$IFACE" ip6 saddr "$IPV6_PREFIX" counter masquerade
  mkdir -p "$DNSMASQ_SHARED_DIR"
  cat >"$DNSMASQ_IPV6_CONF" <<EOF
enable-ra
dhcp-range=::,constructor:$IFACE,ra-stateless,ra-names,12h
dhcp-option=option6:dns-server,[2606:4700:4700::1111],[2001:4860:4860::8888]
EOF
  reload_dnsmasq
  /usr/local/bin/service-lan-ra.py "$IFACE" "$IPV6_PREFIX" "2606:4700:4700::1111" >/tmp/service-lan-ra.log 2>&1 &
  echo $! >"$RA_PID"
else
  rm -f "$DNSMASQ_IPV6_CONF"
  reload_dnsmasq
fi
