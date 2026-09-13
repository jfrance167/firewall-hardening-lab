# Validation Record

Validation was performed on September 13, 2026. This file distinguishes
completed development checks from the pending isolated-VM firewall exercise.

## Completed checks

- Python compilation passed for the scanner, lab services, and tests.
- Both Bash scripts passed `bash -n` syntax validation with Git Bash.
- All 14 automated tests passed with warnings treated as errors.
- The tests include a real loopback TCP listener and verify open versus
  non-open scan behavior.
- A three-service development run started real listeners on ports 8080, 8443,
  and 9000. The scanner recorded all three as open.
- After the development listeners stopped, the scanner recorded all three as
  non-open.
- Synthetic before/after fixtures generated a passing sample report.
- Raw development evidence remained under the Git-ignored `.private/` path.

## Evidence integrity controls checked

- Public targets are rejected unless `--allow-public` is explicitly supplied.
- Port ranges, worker count, and socket timeouts are bounded.
- Evidence is written atomically and validated with a strict schema.
- Duplicate ports, invalid states, invalid timestamps, non-finite numbers, and
  mismatched targets are rejected.
- Report output cannot overwrite either input evidence file.
- A blocked port that was not open in the baseline is reported as
  `not-observed` and cannot produce an overall pass.
- Reapplying the policy validates and replaces the lab table in one nftables
  transaction instead of deleting the active table before validation.

## Isolated VM status

An existing Cisco Ubuntu VirtualBox VM was selected so the Windows host
firewall would not be changed. Its virtual disks and saved-state file are
present. VirtualBox currently returns a machine session-lock error before it
can discard the invalid suspended state. The attempted repair did not change
the VM, its disks, or its firewall.

The real nftables application and remote before/after evidence run remain
pending until the VirtualBox service is restarted successfully. No report in
this repository is represented as real firewall evidence yet.
