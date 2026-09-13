#!/usr/bin/env python3
"""Run harmless TCP banner services for the isolated firewall lab."""

from __future__ import annotations

import argparse
import signal
import socketserver
import threading
from contextlib import ExitStack
from typing import Sequence


DEFAULT_PORTS = (8080, 8443, 9000)


class ReusableThreadingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class BannerHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        port = self.server.server_address[1]
        self.request.sendall(f"firewall-hardening-lab port={port}\n".encode())


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--ports", nargs="+", type=int, default=list(DEFAULT_PORTS))
    args = parser.parse_args(argv)
    if len(set(args.ports)) != len(args.ports):
        parser.error("ports must be unique")
    if not all(1024 <= port <= 65535 for port in args.ports):
        parser.error("lab ports must be between 1024 and 65535")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    stop = threading.Event()
    for signal_name in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signal_name, lambda *_: stop.set())
    with ExitStack() as stack:
        servers = [
            stack.enter_context(
                ReusableThreadingServer((args.bind, port), BannerHandler)
            )
            for port in args.ports
        ]
        threads = [
            threading.Thread(target=server.serve_forever, daemon=True)
            for server in servers
        ]
        for thread in threads:
            thread.start()
        print(f"Listening on {args.bind}: {', '.join(map(str, args.ports))}")
        print("Press Ctrl+C to stop.")
        stop.wait()
        for server in servers:
            server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
