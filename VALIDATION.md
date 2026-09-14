# Validation Record

Validation was performed on September 13, 2026 using a disposable clone of a
Cisco Ubuntu cybersecurity lab VM. The original VM, its virtual disks, and its
broken suspended session were not modified.

## Isolated environment

- Hypervisor: Oracle VirtualBox
- Guest: Ubuntu, kernel family 5.15
- Guest address: `10.0.2.15` behind VirtualBox NAT
- Host scan address: `127.0.0.1`
- Exposure: port forwards bound only to host loopback
- Bridged networking: disabled
- Clipboard and drag-and-drop: disabled
- Rollback snapshot: `pre-firewall-hardening-lab`

VirtualBox NAT terminates the host-side TCP handshake for a forwarded port.
The scanner therefore used `banner` mode, which requires an actual response
from the guest service before classifying a port as open.

## Real before-and-after result

Three harmless Python banner services listened on guest ports 8080, 8443, and
9000. The baseline scan confirmed that all three returned service responses.

The `inet firewall_lab` nftables table then applied a default-deny inbound
policy. It preserved established traffic, loopback, ICMP, DHCP responses, port
8080, and ports 22/8443 from the VirtualBox NAT subnet. Other inbound traffic
was rate-limited for logging and dropped.

| Port | Baseline | Hardened | Expected | Result |
|---:|---|---|---|---|
| 8080 | open | open | allowed | pass |
| 8443 | open | open | allowed | pass |
| 9000 | open | filtered | blocked | pass |

Overall validation: **PASS**

The firewall drop counter recorded two packets during validation. This result
is an investigative control test for the specified ports and source position;
it is not a claim that every guest service or protocol is secure.

## Rollback verification

The rollback script removed only `table inet firewall_lab`. A final banner
probe confirmed port 9000 returned to `open`, proving both that the earlier
filtering was caused by the lab policy and that rollback restored access. The
firewall was left rolled back after testing.

## Private evidence integrity

Raw evidence remains under the Git-ignored `.private/` directory.

| File | Bytes | SHA-256 |
|---|---:|---|
| `before.json` | 607 | `3D561CF513B23EF1D4D9B96EBA8414F9D25506A36D97C199CEAB408F17924F19` |
| `after.json` | 619 | `2CCEFBA6945DF867325482783F59DF1BABAD68E08810B8E69ED6C483D5DEC2C6` |
| `rollback-check.json` | 315 | `9DCD9FE9F81D9FC0FE85BD96326643398F1B98EF9122608EE5C92BBE68AF87A6` |

## Automated verification

- Python compilation passed for the scanner, lab services, and tests.
- Both Bash scripts passed `bash -n` syntax validation.
- All 14 automated tests passed with warnings treated as errors.
- Tests cover port parsing and limits, private-target enforcement, evidence
  schema validation, atomic round trips, comparison failures, inconclusive
  baselines, overwrite protection, and a real loopback TCP listener.
- Synthetic evidence generated the expected passing sample report.

## Evidence-quality controls

- Public targets require explicit `--allow-public` acknowledgement.
- Scan port count, worker count, and socket timeouts are bounded.
- Evidence is written atomically and validated with a strict schema.
- Duplicate ports, invalid states, invalid timestamps, non-finite numbers,
  mismatched targets, and mismatched probe modes are rejected.
- Report output cannot overwrite either input evidence file.
- A policy port that was not open in the baseline is `not-observed` and cannot
  produce an overall pass.
