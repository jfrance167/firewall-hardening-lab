#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 2
fi
command -v nft >/dev/null || {
  echo "nft is required." >&2
  exit 2
}

if nft list table inet firewall_lab >/dev/null 2>&1; then
  nft delete table inet firewall_lab
  echo "Removed scoped table 'inet firewall_lab'."
else
  echo "No firewall_lab table exists; nothing to roll back."
fi
