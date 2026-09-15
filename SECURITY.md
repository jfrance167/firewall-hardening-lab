# Security Policy

## Supported version

Only the latest commit on `main` is maintained.

## Intended use

This repository is an educational firewall lab, not a production baseline.
Apply rules only to isolated systems you own or are authorized to administer,
preserve console access, and verify rollback before testing.

## Reporting a security issue

Use GitHub private vulnerability reporting when available. Do not publish real
credentials, firewall exports, internal addresses, or raw environment evidence.
Revoke and rotate exposed secrets before repository cleanup.

## Maintainer checks

Before publishing, run `pre-commit run --all-files`, the documented test suite,
and GitHub secret scanning. Confirm that private evidence stays untracked.
