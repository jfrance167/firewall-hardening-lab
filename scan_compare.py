#!/usr/bin/env python3
"""Safely scan a private lab host and compare before/after firewall evidence."""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import socket
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Sequence


SCHEMA_VERSION = 1
MAX_PORTS = 1024
VALID_STATES = {"open", "closed", "filtered", "unreachable", "error"}


@dataclass(frozen=True)
class PortResult:
    port: int
    state: str
    latency_ms: float
    detail: str


@dataclass(frozen=True)
class ScanEvidence:
    schema_version: int
    generated_at: str
    target: str
    timeout_seconds: float
    results: list[PortResult]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "target": self.target,
            "timeout_seconds": self.timeout_seconds,
            "results": [asdict(result) for result in self.results],
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_ports(value: str) -> list[int]:
    ports: set[int] = set()
    if not value.strip():
        raise ValueError("port specification cannot be empty")
    for item in value.split(","):
        token = item.strip()
        if not token:
            raise ValueError("empty item in port specification")
        if "-" in token:
            parts = token.split("-")
            if len(parts) != 2 or not all(part.isdigit() for part in parts):
                raise ValueError(f"invalid port range: {token!r}")
            start, end = (int(part) for part in parts)
            if start > end:
                raise ValueError(f"descending port range: {token!r}")
            ports.update(range(start, end + 1))
        elif token.isdigit():
            ports.add(int(token))
        else:
            raise ValueError(f"invalid port: {token!r}")
        if len(ports) > MAX_PORTS:
            raise ValueError(f"at most {MAX_PORTS} unique ports may be scanned")
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def validate_target(value: str, allow_public: bool = False) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("target must be an IP address literal") from exc
    if address.is_multicast or address.is_unspecified:
        raise ValueError("multicast and unspecified targets are not allowed")
    permitted = address.is_private or address.is_loopback or address.is_link_local
    if not permitted and not allow_public:
        raise ValueError("public targets require the explicit --allow-public option")
    return str(address)


def classify_socket_error(error: OSError) -> tuple[str, str]:
    code = error.errno
    win_code = getattr(error, "winerror", None)
    if isinstance(error, ConnectionRefusedError) or code in {61, 111} or win_code == 10061:
        return "closed", "connection refused"
    if isinstance(error, TimeoutError) or code in {60, 110} or win_code == 10060:
        return "filtered", "connection timed out"
    if code in {51, 65, 101, 113} or win_code in {10051, 10065}:
        return "unreachable", "network or host unreachable"
    return "error", f"socket error {win_code or code or 'unknown'}"


def scan_port(target: str, port: int, timeout: float) -> PortResult:
    started = perf_counter()
    state = "open"
    detail = "TCP connection completed"
    try:
        with socket.create_connection((target, port), timeout=timeout):
            pass
    except OSError as exc:
        state, detail = classify_socket_error(exc)
    latency = round((perf_counter() - started) * 1000, 2)
    return PortResult(port, state, latency, detail)


def scan_target(
    target: str, ports: Sequence[int], timeout: float, workers: int
) -> ScanEvidence:
    if not ports or len(set(ports)) != len(ports):
        raise ValueError("ports must be a nonempty sequence of unique values")
    if not all(type(port) is int and 1 <= port <= 65535 for port in ports):
        raise ValueError("ports must be integers between 1 and 65535")
    if timeout <= 0 or timeout > 30:
        raise ValueError("timeout must be greater than 0 and at most 30 seconds")
    if workers < 1 or workers > 256:
        raise ValueError("workers must be between 1 and 256")
    results: list[PortResult] = []
    with ThreadPoolExecutor(max_workers=min(workers, len(ports))) as executor:
        futures = {
            executor.submit(scan_port, target, port, timeout): port for port in ports
        }
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda result: result.port)
    return ScanEvidence(SCHEMA_VERSION, utc_now(), target, timeout, results)


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content.rstrip() + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def save_evidence(evidence: ScanEvidence, path: Path) -> None:
    atomic_write(path, json.dumps(evidence.to_dict(), indent=2))


def load_evidence(path: Path) -> ScanEvidence:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read evidence {path}: {exc}") from exc
    expected = {
        "schema_version", "generated_at", "target", "timeout_seconds", "results"
    }
    if not isinstance(document, dict) or set(document) != expected:
        raise ValueError(f"invalid evidence structure in {path}")
    if document["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"unsupported evidence schema in {path}")
    if not isinstance(document["generated_at"], str):
        raise ValueError(f"invalid evidence metadata in {path}")
    if not isinstance(document["target"], str):
        raise ValueError(f"invalid evidence metadata in {path}")
    timeout_value = document["timeout_seconds"]
    if isinstance(timeout_value, bool) or not isinstance(timeout_value, (int, float)):
        raise ValueError(f"invalid evidence metadata in {path}")
    try:
        generated = datetime.fromisoformat(document["generated_at"].replace("Z", "+00:00"))
        if generated.tzinfo is None:
            raise ValueError
        validate_target(document["target"], allow_public=True)
        timeout = float(timeout_value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"invalid evidence metadata in {path}") from exc
    if (
        not math.isfinite(timeout)
        or timeout <= 0
        or timeout > 30
        or not isinstance(document["results"], list)
        or len(document["results"]) > MAX_PORTS
    ):
        raise ValueError(f"invalid evidence metadata in {path}")
    results: list[PortResult] = []
    seen: set[int] = set()
    for item in document["results"]:
        if not isinstance(item, dict) or set(item) != {
            "port", "state", "latency_ms", "detail"
        }:
            raise ValueError(f"invalid port result in {path}")
        port = item["port"]
        state = item["state"]
        if type(port) is not int or not 1 <= port <= 65535 or port in seen:
            raise ValueError(f"invalid or duplicate port result in {path}")
        if not isinstance(state, str) or state not in VALID_STATES:
            raise ValueError(f"invalid port state in {path}")
        latency = item["latency_ms"]
        if (
            isinstance(latency, bool)
            or not isinstance(latency, (int, float))
            or not math.isfinite(latency)
            or latency < 0
        ):
            raise ValueError(f"invalid latency in {path}")
        if not isinstance(item["detail"], str):
            raise ValueError(f"invalid detail in {path}")
        seen.add(port)
        results.append(PortResult(port, state, float(latency), item["detail"]))
    return ScanEvidence(
        SCHEMA_VERSION,
        generated.astimezone(timezone.utc).isoformat(timespec="seconds"),
        document["target"],
        timeout,
        sorted(results, key=lambda result: result.port),
    )


def load_policy(path: Path) -> dict[str, object]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read policy {path}: {exc}") from exc
    if not isinstance(document, dict) or set(document) != {
        "name", "allowed_ports", "blocked_ports"
    }:
        raise ValueError("invalid policy structure")
    if not isinstance(document["name"], str) or not document["name"]:
        raise ValueError("policy name must be a nonempty string")
    allowed = document["allowed_ports"]
    blocked = document["blocked_ports"]
    if not isinstance(allowed, list) or not isinstance(blocked, list):
        raise ValueError("policy port lists must be arrays")
    if not all(type(port) is int and 1 <= port <= 65535 for port in allowed + blocked):
        raise ValueError("policy ports must be integers between 1 and 65535")
    if len(set(allowed)) != len(allowed) or len(set(blocked)) != len(blocked):
        raise ValueError("policy port lists cannot contain duplicates")
    if set(allowed) & set(blocked):
        raise ValueError("a policy port cannot be both allowed and blocked")
    return document


def compare_evidence(
    before: ScanEvidence, after: ScanEvidence, policy: dict[str, object]
) -> tuple[list[dict[str, object]], bool]:
    if before.target != after.target:
        raise ValueError("before and after evidence target different hosts")
    before_by_port = {result.port: result for result in before.results}
    after_by_port = {result.port: result for result in after.results}
    required = set(policy["allowed_ports"]) | set(policy["blocked_ports"])
    missing = required - (before_by_port.keys() & after_by_port.keys())
    if missing:
        raise ValueError(f"evidence is missing policy ports: {sorted(missing)}")
    rows: list[dict[str, object]] = []
    passed = True
    for port in sorted(required):
        prior = before_by_port[port].state
        current = after_by_port[port].state
        expectation = "allowed" if port in policy["allowed_ports"] else "blocked"
        if prior != "open":
            outcome = "not-observed"
        elif expectation == "allowed":
            outcome = "pass" if current == "open" else "fail"
        else:
            outcome = "pass" if current in {"closed", "filtered"} else "fail"
        passed = passed and outcome == "pass"
        rows.append(
            {
                "port": port,
                "before": prior,
                "after": current,
                "expectation": expectation,
                "outcome": outcome,
            }
        )
    return rows, passed


def render_report(
    before: ScanEvidence,
    after: ScanEvidence,
    policy: dict[str, object],
    rows: Sequence[dict[str, object]],
    passed: bool,
) -> str:
    mitigated = sum(
        row["before"] == "open" and row["after"] != "open" for row in rows
    )
    status = "PASS" if passed else "FAIL"
    lines = [
        "# Firewall Hardening Validation Report",
        "",
        f"- Policy: `{policy['name']}`",
        f"- Target: `{before.target}`",
        f"- Baseline captured: {before.generated_at}",
        f"- Hardened scan captured: {after.generated_at}",
        f"- Validation result: **{status}**",
        f"- Previously open ports mitigated: {mitigated}",
        "",
        "## Before and after",
        "",
        "| Port | Before | After | Expected | Result |",
        "|---:|---|---|---|---|",
    ]
    lines.extend(
        f"| {row['port']} | {row['before']} | {row['after']} | "
        f"{row['expectation']} | {row['outcome']} |"
        for row in rows
    )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "A blocked or filtered port shows that TCP access was prevented from the "
            "scanner's network position. An allowed port remaining open confirms "
            "required connectivity survived the policy change.",
            "",
            "This result applies only to the tested target, ports, source network, "
            "time, and protocol. It does not prove that every host exposure is secure.",
            "",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="scan a private lab target")
    scan.add_argument("target")
    scan.add_argument("--ports", required=True, help="comma-separated ports/ranges")
    scan.add_argument("--output", required=True, type=Path)
    scan.add_argument("--timeout", type=float, default=1.0)
    scan.add_argument("--workers", type=int, default=64)
    scan.add_argument("--allow-public", action="store_true")
    compare = subparsers.add_parser("compare", help="compare scan evidence")
    compare.add_argument("--before", required=True, type=Path)
    compare.add_argument("--after", required=True, type=Path)
    compare.add_argument("--policy", required=True, type=Path)
    compare.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            target = validate_target(args.target, args.allow_public)
            ports = parse_ports(args.ports)
            evidence = scan_target(target, ports, args.timeout, args.workers)
            save_evidence(evidence, args.output.resolve())
            counts: dict[str, int] = {}
            for result in evidence.results:
                counts[result.state] = counts.get(result.state, 0) + 1
            print(json.dumps({"output": str(args.output), "states": counts}))
            return 0
        before_path = args.before.resolve()
        after_path = args.after.resolve()
        output_path = args.output.resolve()
        if output_path in {before_path, after_path}:
            raise ValueError("report output must not overwrite scan evidence")
        before = load_evidence(before_path)
        after = load_evidence(after_path)
        policy = load_policy(args.policy.resolve())
        rows, passed = compare_evidence(before, after, policy)
        atomic_write(output_path, render_report(before, after, policy, rows, passed))
        print(json.dumps({"output": str(args.output), "validation": passed}))
        return 0 if passed else 1
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
