#!/usr/bin/env python3
"""S1 receiver: logs exactly what the iOS App Intent posted.

Plaintext by design — this spike has no crypto (that is T1). Do not point real
secrets at it beyond the throwaway TOTP codes the test matrix calls for.
"""

import argparse
import datetime
import json
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 64 * 1024

args = None

_seq = 0
_seq_lock = threading.Lock()


def next_seq() -> int:
    global _seq
    with _seq_lock:
        _seq += 1
        return _seq


def stamp() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/health":
            self._reply(200, {"ok": True})
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self):
        n = next_seq()
        arrived = time.monotonic()
        length = int(self.headers.get("Content-Length") or 0)

        if length > MAX_BODY:
            self._reply(413, {"error": "too large"})
            return

        raw = self.rfile.read(length) if length else b""

        print(f"\n=== #{n} {stamp()} POST {self.path} from {self.client_address[0]} ===")
        print(f"  content-type : {self.headers.get('Content-Type')}")
        print(f"  raw bytes    : {len(raw)}")
        print(f"  raw body     : {raw!r}")

        if args.delay:
            print(f"  holding response for {args.delay}s (timeout probe)")
            time.sleep(args.delay)

        if args.fail:
            print(f"  replying {args.fail} (forced failure probe)")
            self._reply(args.fail, {"error": "forced failure"})
            return

        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            print(f"  !! body is not UTF-8 JSON: {exc}")
            self._reply(400, {"error": "bad json"})
            return

        text = payload.get("text")
        print(f"  json keys    : {sorted(payload)}")
        print(f"  text type    : {type(text).__name__}  <-- must be 'str'")
        print(f"  text repr    : {text!r}")

        if isinstance(text, str):
            b = text.encode("utf-8")
            print(f"  utf8 hex     : {b.hex(' ')}")
            print(f"  codepoints   : {[hex(ord(c)) for c in text]}")
            print(f"  leading zero : {'YES' if text.startswith('0') else 'no'}")
            print(f"  len (app)    : utf8={payload.get('utf8Length')} chars={payload.get('characterCount')}")
            print(f"  len (here)   : utf8={len(b)} chars={len(text)}")
            if payload.get("utf8Length") not in (None, len(b)):
                print("  !! LENGTH MISMATCH between app and receiver")
        else:
            print("  !! FAIL: text was not a JSON string — it was coerced on the way in")

        served = time.monotonic() - arrived
        self._reply(200, {"ok": True, "seq": n, "echo": text, "heldMs": round(served * 1000)})

    def _reply(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def local_addresses(port):
    """Every IPv4 on the box, so the tailnet address (100.x, on a utun) shows up
    too — getaddrinfo on the hostname misses VPN interfaces."""
    addrs = set()
    try:
        out = subprocess.run(["/sbin/ifconfig", "-a"], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet ") and not line.startswith("inet 127."):
                addrs.add(line.split()[1])
    except Exception:
        pass
    if not addrs:
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                addrs.add(info[4][0])
        except Exception:
            pass
    tailnet = sorted(a for a in addrs if a.startswith("100."))
    other = sorted(a for a in addrs if not a.startswith("100."))
    return [f"http://{a}:{port}/clip" for a in tailnet + other]


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--delay", type=float, default=0.0,
                   help="hold the response this many seconds (network-timeout probe)")
    p.add_argument("--fail", type=int, default=0,
                   help="always reply with this HTTP status (failure-surfacing probe)")
    args = p.parse_args()
    sys.stdout.reconfigure(line_buffering=True)

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"S1 receiver on {args.host}:{args.port}  (POST /clip, GET /health)")
    for url in local_addresses(args.port):
        print(f"  try: {url}")
    print("Ctrl-C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
        sys.exit(0)
