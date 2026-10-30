#!/usr/bin/env python3
"""Native load/count and positive/negative matching gates; all traffic is rejected locally."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import http.client
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
PIN_URL = "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-compatible-v1.19.33.gz"
PIN_SHA256 = "386508bfb1c72c43b6a0eda73708ecdce82546581b0ebcb16366c53757c622b6"


def install_binary(target: Path) -> None:
    with urlopen(PIN_URL, timeout=120) as response:
        data = response.read(64 * 1024 * 1024 + 1)
    if hashlib.sha256(data).hexdigest() != PIN_SHA256:
        raise RuntimeError("Mihomo download checksum mismatch")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(gzip.decompress(data))
    target.chmod(0o755)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def validate_native(binary: Path, providers: dict, cases: list[tuple[str, str]]) -> None:
    """providers: name -> (path, behavior, format, expected count or None)."""
    with tempfile.TemporaryDirectory(prefix="rules-native-") as temp:
        home = Path(temp)
        mixed, controller = free_port(), free_port()
        while controller == mixed:
            controller = free_port()
        provider_config = {}
        for name, (source, behavior, fmt, _) in providers.items():
            target = home / (name + "." + fmt)
            target.write_bytes(Path(source).read_bytes())
            provider_config[name] = {"type": "file", "path": "./" + target.name,
                                     "behavior": behavior, "format": fmt}
        names = ["hit_" + name for name in providers] + ["miss"]
        config = {"mixed-port": mixed, "external-controller": "127.0.0.1:" + str(controller),
                  "bind-address": "127.0.0.1", "allow-lan": False, "mode": "rule",
                  "log-level": "info", "ipv6": False, "rule-providers": provider_config,
                  "proxy-groups": [{"name": n, "type": "select", "proxies": ["REJECT"]}
                                   for n in names],
                  "rules": ["RULE-SET," + n + ",hit_" + n for n in providers] + ["MATCH,miss"]}
        path = home / "config.json"
        path.write_text(json.dumps(config))
        proc = subprocess.Popen([str(binary.resolve()), "-d", str(home), "-f", str(path)],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
        logs = []
        condition = threading.Condition()
        def capture():
            assert proc.stdout is not None
            for line in proc.stdout:
                with condition:
                    logs.append(line.rstrip())
                    condition.notify_all()
        reader = threading.Thread(target=capture, daemon=True)
        reader.start()
        def api(method, resource):
            connection = http.client.HTTPConnection("127.0.0.1", controller, timeout=10)
            try:
                connection.request(method, resource)
                response = connection.getresponse()
                data = response.read()
                return response.status, json.loads(data) if data else None
            finally:
                connection.close()
        try:
            deadline = time.monotonic() + 60
            while True:
                if proc.poll() is not None:
                    raise AssertionError("Mihomo exited during initialization: " + "\n".join(logs))
                try:
                    status, data = api("GET", "/providers/rules")
                    loaded = (data or {}).get("providers") or {}
                    _, proxies = api("GET", "/proxies")
                    if status == 200 and set(loaded) == set(providers) and all(
                        name in (proxies or {}).get("proxies", {}) for name in names
                    ) and all(loaded[n]["ruleCount"] > 0 or providers[n][3] == 0 for n in providers):
                        break
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    raise AssertionError("Mihomo did not initialize all providers: " + "\n".join(logs))
                with condition:
                    condition.wait(timeout=0.05)
            for name, (_, _, _, expected) in providers.items():
                status, _ = api("PUT", "/providers/rules/" + name)
                assert status == 204, (name, status)
            _, data = api("GET", "/providers/rules")
            for name, (_, _, _, expected) in providers.items():
                if expected is not None:
                    assert data["providers"][name]["ruleCount"] == expected, (
                        name, expected, data["providers"][name]["ruleCount"])
            for host, expected in cases:
                # The controller/provider APIs can be ready before compatible
                # proxy groups finish initialization. Retry only an idempotent
                # local sample with no routing evidence, never a wrong match.
                route = None
                for _attempt in range(2):
                    start = len(logs)
                    connection = http.client.HTTPConnection("127.0.0.1", mixed, timeout=10)
                    try:
                        connection.request("GET", "http://" + host + "/native-rule-test")
                        response = connection.getresponse()
                        response.read()
                    finally:
                        connection.close()
                    with condition:
                        found = condition.wait_for(
                            lambda host=host, start=start: any(
                                host + ":80" in line and " using " in line
                                for line in logs[start:]
                            ), timeout=5,
                        )
                        if found:
                            route = next(line for line in reversed(logs[start:])
                                         if host + ":80" in line and " using " in line)
                            break
                assert route is not None, (host, logs)
                assert "using " + expected + "[REJECT]" in route, (host, expected, route)
            bad = [line for line in logs if "skip invalid" in line or "parse classical rule" in line
                   or "level=error" in line or "level=fatal" in line]
            assert not bad, "\n".join(bad)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
            reader.join(timeout=5)
            if proc.stdout:
                proc.stdout.close()


def main() -> None:
    import sync_rules
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path(os.environ.get("MIHOMO_BINARY", ROOT / ".tools/mihomo")))
    parser.add_argument("--install", action="store_true", help="download the checksum-pinned Linux amd64 CLI")
    args = parser.parse_args()
    if args.install:
        install_binary(args.binary)
    if not args.binary.is_file():
        parser.error("set --binary or MIHOMO_BINARY, or use --install on Linux amd64")
    with tempfile.TemporaryDirectory(prefix="pcdn-fixture-") as temporary:
        fixture = Path(temporary) / "fixture.yaml"
        parsed = sync_rules.parse_source("DOMAIN,exact.fixture.invalid\nDOMAIN-SUFFIX,suffix.fixture.invalid\n||apd-*.wild.fixture.invalid^")
        fixture.write_text(sync_rules.render_clash(parsed.rules, []))
        published = sync_rules.parse_source((ROOT / "pcdn_block_clash.yaml").read_text(), source_format="clash")
        validate_native(args.binary, {
            "fixture": (fixture, "classical", "yaml", parsed.rules.count()),
            "published": (ROOT / "pcdn_block_clash.yaml", "classical", "yaml", published.rules.count()),
        }, [("exact.fixture.invalid", "hit_fixture"), ("child.exact.fixture.invalid", "miss"),
            ("child.suffix.fixture.invalid", "hit_fixture"),
            ("apd-demo.wild.fixture.invalid", "hit_fixture"),
            ("child.apd-demo.wild.fixture.invalid", "hit_fixture"),
            ("other.wild.fixture.invalid", "miss"), ("control.example.invalid", "miss")])
    print("PASS: published rule counts and native positive/negative matches")


if __name__ == "__main__":
    main()
