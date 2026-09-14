#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo $0 <trusted-admin-ipv4-cidr>" >&2
  exit 2
fi
if [[ $# -ne 1 ]]; then
  echo "Usage: sudo $0 <trusted-admin-ipv4-cidr>" >&2
  exit 2
fi
command -v nft >/dev/null || {
  echo "nft is required (Ubuntu package: nftables)." >&2
  exit 2
}

admin_cidr=$1
python3 - "$admin_cidr" <<'PY'
import ipaddress
import sys

network = ipaddress.ip_network(sys.argv[1], strict=False)
if network.version != 4 or not (network.is_private or network.is_link_local):
    raise SystemExit("trusted admin CIDR must be a private IPv4 network")
PY

temporary_rules=$(mktemp)
trap 'rm -f "$temporary_rules"' EXIT
table_exists=false
if nft list table inet firewall_lab >/dev/null 2>&1; then
  table_exists=true
fi

{
  if [[ $table_exists == true ]]; then
    echo "delete table inet firewall_lab"
  fi
  cat <<EOF
table inet firewall_lab {
  chain input {
    type filter hook input priority 10; policy drop;
    ct state invalid drop
    ct state established,related accept
    iifname "lo" accept
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept
    udp sport 67 udp dport 68 accept
    ip saddr $admin_cidr tcp dport { 22, 8443 } accept
    tcp dport 8080 accept
    limit rate 5/minute counter log prefix "firewall-lab-drop " drop
  }
  chain output {
    type filter hook output priority 10; policy accept;
  }
}
EOF
} >"$temporary_rules"

nft --check --file "$temporary_rules"
nft --file "$temporary_rules"
nft list table inet firewall_lab
echo "Applied scoped table 'inet firewall_lab'."
echo "Rollback: sudo ./rollback_firewall.sh"
