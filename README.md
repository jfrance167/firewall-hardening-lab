# Firewall Hardening Lab

A defensive networking lab that measures TCP exposure, applies a narrowly
scoped Linux `nftables` policy, and produces a before-and-after validation
report. The project emphasizes safe rollback, repeatable evidence, and honest
interpretation rather than treating a single port scan as proof of security.

Use it only against systems you own or are authorized to test.

## Objective

Demonstrate an end-to-end host-hardening workflow:

1. Run harmless services on an isolated Ubuntu virtual machine.
2. Capture a baseline scan through loopback-only VirtualBox NAT forwards.
3. Apply a default-deny inbound firewall policy.
4. Preserve required access while blocking an unnecessary service.
5. Rescan from the same source and compare the evidence automatically.
6. Roll back only the lab's firewall table.

## Lab topology

```text
Windows host / scanner          VirtualBox NAT          Isolated Ubuntu VM
127.0.0.1 only             ->  loopback forwards  ->   10.0.2.15
                                                       8080 allowed
                                                       8443 admin-only
                                                       9000 blocked
```

The VM uses NAT for outbound access. VirtualBox forwards only the tested ports
to host loopback, so the services are not exposed to the physical LAN. Bridged
networking is not used. Banner probing requires an actual guest response and
avoids treating the NAT listener itself as proof that a service is reachable.

## Security design

- The scanner accepts private, loopback, and link-local IP literals by default.
- Public targets require an explicit `--allow-public` acknowledgement.
- A scan is limited to 1,024 unique ports and 256 workers.
- Evidence is written atomically and strictly validated before comparison.
- Report output cannot overwrite the original scan evidence.
- The firewall lives in its own `inet firewall_lab` table.
- Existing lab rules are replaced through one checked nftables transaction.
- Rollback deletes only that table; it does not flush unrelated firewall rules.
- Raw environment-specific evidence belongs in `.private/` and is Git-ignored.

## Project contents

- `lab_services.py` — harmless TCP banner services for ports 8080, 8443, 9000
- `scan_compare.py` — safe scanner, evidence validator, comparison, and report
- `apply_firewall.sh` — atomic nftables validation and scoped policy application
- `rollback_firewall.sh` — idempotent removal of only the lab table
- `config/policy.json` — machine-readable expected allowed/blocked ports
- `samples/` — clearly labeled synthetic evidence for demonstrating reporting
- `reports/sample-report.md` — report generated from the synthetic evidence
- `reports/firewall-validation-report.md` — sanitized real VM result
- `VALIDATION.md` — completed checks and the current isolated-VM evidence status
- `tests/` — validation, comparison, safety, CLI, and live-socket tests

## Prerequisites

On the Ubuntu VM:

```bash
sudo apt-get update
sudo apt-get install -y nftables python3
```

The Windows host needs Python 3.10 or newer. The project scanner uses only the
standard library; Nmap is optional for independent confirmation.

## Run the lab

Copy `lab_services.py`, `apply_firewall.sh`, and `rollback_firewall.sh` to the
isolated VM. In the VM, start the harmless services:

```bash
python3 lab_services.py
```

From Windows, scan the loopback-only VirtualBox forwards:

```powershell
python scan_compare.py scan 127.0.0.1 `
  --ports 8080,8443,9000 `
  --probe-mode banner `
  --output .private\before.json
```

Confirm that all three lab ports are open. Then apply the firewall from the VM
console, supplying the VirtualBox NAT subnet:

```bash
sudo ./apply_firewall.sh 10.0.2.0/24
```

The policy permits established traffic, loopback, ICMP, DHCP responses, port
8080 from any source, and ports 22/8443 from the VirtualBox NAT admin subnet.
All other inbound traffic is logged at a limited rate and dropped.

Capture hardened evidence from the same Windows source:

```powershell
python scan_compare.py scan 127.0.0.1 `
  --ports 8080,8443,9000 `
  --probe-mode banner `
  --output .private\after.json

python scan_compare.py compare `
  --before .private\before.json `
  --after .private\after.json `
  --policy config\policy.json `
  --output reports\live-validation.md
```

A successful result keeps 8080 and 8443 responsive from the trusted host while
port 9000 stops returning its service banner and becomes filtered or closed.

## Rollback

Use the VM console if a rule unexpectedly interrupts remote access:

```bash
sudo ./rollback_firewall.sh
```

The policy is intentionally not persisted across reboot. A VM reboot is a
secondary recovery path. The pre-lab VM snapshot provides a final rollback.

## Demonstrate report generation

The included files are synthetic and exist only to exercise the report path:

```powershell
python scan_compare.py compare `
  --before samples\before.json `
  --after samples\after.json `
  --policy config\policy.json `
  --output reports\sample-report.md
```

## Test

```powershell
python -W error -m unittest discover -s tests -v
```

GitHub Actions runs compilation and all tests with Python 3.10 and 3.13 on
Windows and Ubuntu. Linux runners also parse both shell scripts.

## Completed validation

The isolated VM exercise passed: ports 8080 and 8443 remained responsive while
port 9000 changed from open to filtered. The scoped rollback was then applied,
and port 9000 returned to open. See `VALIDATION.md` for environment details and
evidence hashes, and `reports/firewall-validation-report.md` for the sanitized
before-and-after table.

## Interpretation and limitations

- In connect mode, `open` means a TCP connection completed.
- In banner mode, `open` also requires a response from the guest service.
- `closed` generally means the host actively refused the connection.
- `filtered` means the connection timed out; a firewall is one possible cause.
- Results cover only the tested ports, address, source network, and time.
- The lab does not assess UDP, IPv6 reachability beyond the policy basics,
  application vulnerabilities, authentication, or services on other hosts.
- A real deployment requires change control, persistent-rule planning,
  monitoring, documented business requirements, and testing from each zone.

## Portfolio summary

> Built an isolated Linux firewall-hardening lab using Python and nftables,
> measured service exposure before and after a default-deny policy, preserved
> authorized access, automated evidence comparison, and implemented scoped
> rollback and CI testing.
