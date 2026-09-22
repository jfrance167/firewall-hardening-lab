from __future__ import annotations

import json
import socketserver
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

import scan_compare as scanner


class PortParsingTests(unittest.TestCase):
    def test_parses_ports_ranges_and_duplicates(self) -> None:
        self.assertEqual(scanner.parse_ports("8080,8443,8443,9000-9002"), [
            8080, 8443, 9000, 9001, 9002
        ])

    def test_rejects_invalid_and_excessive_ports(self) -> None:
        for value in ("", "0", "65536", "90-80", "80,,443", "abc"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                scanner.parse_ports(value)
        with self.assertRaisesRegex(ValueError, "at most"):
            scanner.parse_ports("1-1025")

    def test_private_target_is_default_and_public_requires_opt_in(self) -> None:
        self.assertEqual(scanner.validate_target("192.168.56.10"), "192.168.56.10")
        with self.assertRaisesRegex(ValueError, "--allow-public"):
            scanner.validate_target("8.8.8.8")
        self.assertEqual(scanner.validate_target("8.8.8.8", True), "8.8.8.8")

    def test_hostnames_and_unspecified_targets_are_rejected(self) -> None:
        for value in ("localhost", "0.0.0.0", "::"):  # nosec B104 -- rejection test
            with self.subTest(value=value), self.assertRaises(ValueError):
                scanner.validate_target(value)


class EvidenceTests(unittest.TestCase):
    def make_evidence(self, states: dict[int, str]) -> scanner.ScanEvidence:
        return scanner.ScanEvidence(
            schema_version=2,
            generated_at="2026-09-13T12:00:00+00:00",
            target="192.168.56.10",
            timeout_seconds=1.0,
            probe_mode="connect",
            results=[
                scanner.PortResult(port, state, 1.5, "test")
                for port, state in sorted(states.items())
            ],
        )

    def test_evidence_round_trip(self) -> None:
        evidence = self.make_evidence({8080: "open", 9000: "closed"})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "evidence.json"
            scanner.save_evidence(evidence, path)
            loaded = scanner.load_evidence(path)
        self.assertEqual(loaded, evidence)

    def test_rejects_duplicate_port_evidence(self) -> None:
        evidence = self.make_evidence({8080: "open"}).to_dict()
        evidence["results"].append(dict(evidence["results"][0]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(evidence), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                scanner.load_evidence(path)

    def test_comparison_passes_when_blocked_port_is_mitigated(self) -> None:
        before = self.make_evidence({8080: "open", 8443: "open", 9000: "open"})
        after = self.make_evidence({8080: "open", 8443: "open", 9000: "filtered"})
        policy = {
            "name": "test",
            "allowed_ports": [8080, 8443],
            "blocked_ports": [9000],
        }
        rows, passed = scanner.compare_evidence(before, after, policy)
        self.assertTrue(passed)
        self.assertEqual(rows[-1]["outcome"], "pass")

    def test_comparison_fails_when_required_or_blocked_state_is_wrong(self) -> None:
        before = self.make_evidence({8080: "open", 9000: "open"})
        after = self.make_evidence({8080: "closed", 9000: "open"})
        policy = {
            "name": "test",
            "allowed_ports": [8080],
            "blocked_ports": [9000],
        }
        rows, passed = scanner.compare_evidence(before, after, policy)
        self.assertFalse(passed)
        self.assertEqual([row["outcome"] for row in rows], ["fail", "fail"])

    def test_comparison_is_inconclusive_without_open_baseline(self) -> None:
        before = self.make_evidence({8080: "closed", 9000: "filtered"})
        after = self.make_evidence({8080: "open", 9000: "filtered"})
        policy = {
            "name": "test",
            "allowed_ports": [8080],
            "blocked_ports": [9000],
        }
        rows, passed = scanner.compare_evidence(before, after, policy)
        self.assertFalse(passed)
        self.assertEqual([row["outcome"] for row in rows], [
            "not-observed", "not-observed"
        ])

    def test_comparison_requires_matching_targets_and_complete_ports(self) -> None:
        before = self.make_evidence({8080: "open"})
        other = scanner.ScanEvidence(
            2,
            before.generated_at,
            "192.168.56.11",
            1.0,
            "connect",
            before.results,
        )
        policy = {"name": "test", "allowed_ports": [8080], "blocked_ports": []}
        with self.assertRaisesRegex(ValueError, "different hosts"):
            scanner.compare_evidence(before, other, policy)
        incomplete = self.make_evidence({9000: "open"})
        with self.assertRaisesRegex(ValueError, "missing"):
            scanner.compare_evidence(before, incomplete, policy)

    def test_report_states_scope_and_result(self) -> None:
        before = self.make_evidence({8080: "open", 9000: "open"})
        after = self.make_evidence({8080: "open", 9000: "filtered"})
        policy = {
            "name": "test",
            "allowed_ports": [8080],
            "blocked_ports": [9000],
        }
        rows, passed = scanner.compare_evidence(before, after, policy)
        report = scanner.render_report(before, after, policy, rows, passed)
        self.assertIn("Validation result: **PASS**", report)
        self.assertIn("does not prove", report)


class LiveSocketTests(unittest.TestCase):
    def test_scan_distinguishes_open_and_nonopen_local_ports(self) -> None:
        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                return

        with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            result = scanner.scan_port("127.0.0.1", port, 1.0)
            server.shutdown()
        self.assertEqual(result.state, "open")
        nonopen = scanner.scan_port("127.0.0.1", port, 1.0)
        self.assertNotEqual(nonopen.state, "open")

    def test_scan_parameter_bounds(self) -> None:
        with self.assertRaises(ValueError):
            scanner.scan_target("127.0.0.1", [80], 0, 1)
        with self.assertRaises(ValueError):
            scanner.scan_target("127.0.0.1", [80], 1, 0)
        with self.assertRaises(ValueError):
            scanner.scan_target("127.0.0.1", [80], 1, 1, "active")


class CliTests(unittest.TestCase):
    def test_compare_refuses_to_overwrite_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = root / "before.json"
            after = root / "after.json"
            policy = root / "policy.json"
            before.write_text("{}", encoding="utf-8")
            after.write_text("{}", encoding="utf-8")
            policy.write_text("{}", encoding="utf-8")
            original = before.read_text(encoding="utf-8")
            with redirect_stderr(StringIO()):
                result = scanner.main([
                    "compare", "--before", str(before), "--after", str(after),
                    "--policy", str(policy), "--output", str(before)
                ])
            self.assertEqual(result, 2)
            self.assertEqual(before.read_text(encoding="utf-8"), original)


if __name__ == "__main__":
    unittest.main()