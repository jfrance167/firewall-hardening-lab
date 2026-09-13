# Firewall Hardening Validation Report

- Policy: `isolated-ubuntu-lab-v1`
- Target: `192.168.56.10`
- Baseline captured: 2026-09-13T14:00:00+00:00
- Hardened scan captured: 2026-09-13T14:10:00+00:00
- Validation result: **PASS**
- Previously open ports mitigated: 1

## Before and after

| Port | Before | After | Expected | Result |
|---:|---|---|---|---|
| 8080 | open | open | allowed | pass |
| 8443 | open | open | allowed | pass |
| 9000 | open | filtered | blocked | pass |

## Interpretation

A blocked or filtered port shows that TCP access was prevented from the scanner's network position. An allowed port remaining open confirms required connectivity survived the policy change.

This result applies only to the tested target, ports, source network, time, and protocol. It does not prove that every host exposure is secure.
