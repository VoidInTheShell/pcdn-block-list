#!/usr/bin/env python3
"""Fetch PCDN sources, normalize their syntax, and render ADH/Clash rules.

The parser intentionally accepts only domain-oriented AdGuard and Clash
syntax.  Unknown non-comment lines fail the run instead of being silently
dropped, so an upstream format change cannot replace a working list with a
partial list.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Sequence, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "sources.json"
OUTPUT_FILES = {
    "adh": ROOT / "pcdn_block_adh.txt",
    "clash": ROOT / "pcdn_block_clash.yaml",
    "lock": ROOT / "sources.lock.json",
}
USER_AGENT = "pcdn-block-list-sync/1.0 (+https://github.com/VoidInTheShell/pcdn-block-list)"
STRUCTURAL_KEYS = {
    "behavior",
    "description",
    "format",
    "name",
    "payload",
    "rules",
    "type",
    "version",
}
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9*-]+$", re.IGNORECASE)
RULE_PREFIX_RE = re.compile(r"^(DOMAIN(?:-SUFFIX|-REGEX)?),(.*)$", re.IGNORECASE)


class RuleParseError(ValueError):
    """Raised when an upstream line cannot be safely represented."""


class FetchError(RuntimeError):
    """Raised when a required upstream cannot be fetched."""


@dataclass
class ParsedSource:
    rules: "RuleSet"
    recognized_lines: int


class RuleSet:
    """Canonical rule buckets used by both renderers."""

    def __init__(self) -> None:
        self.suffix: Set[str] = set()
        self.exact: Set[str] = set()
        self.wildcard: Set[str] = set()
        self.regex: Set[str] = set()

    def add(self, kind: str, value: str) -> bool:
        bucket = getattr(self, kind)
        before = len(bucket)
        bucket.add(value)
        return len(bucket) != before

    def merge(self, other: "RuleSet") -> None:
        self.suffix.update(other.suffix)
        self.exact.update(other.exact)
        self.wildcard.update(other.wildcard)
        self.regex.update(other.regex)

    def effective(self) -> Dict[str, Set[str]]:
        # A suffix rule already covers the exact domain in both target
        # formats.  Removing the redundant exact entry keeps output small and
        # avoids making the two generated files look inconsistent.
        return {
            "suffix": set(self.suffix),
            "exact": self.exact - self.suffix,
            "wildcard": set(self.wildcard),
            "regex": set(self.regex),
        }

    def count(self) -> int:
        effective = self.effective()
        return sum(len(values) for values in effective.values())


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1].strip()
    return value


def normalize_domain(value: str) -> str:
    """Normalize a DNS name or a simple AdGuard host wildcard."""

    value = _strip_quotes(value).strip().lower().rstrip(".")
    if not value or any(char in value for char in "/\\,:?#\t "):
        raise RuleParseError(f"invalid domain {value!r}")
    labels = value.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        raise RuleParseError(f"invalid domain {value!r}")
    for index, label in enumerate(labels):
        if not DOMAIN_LABEL_RE.fullmatch(label):
            raise RuleParseError(f"invalid domain {value!r}")
        if label.startswith("-") or label.endswith("-"):
            raise RuleParseError(f"invalid domain {value!r}")
        if "*" not in label:
            try:
                # Preserve ordinary ASCII spelling but accept IDN input in a
                # deterministic punycode form if an upstream ever adds one.
                encoded = label.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise RuleParseError(f"invalid domain {value!r}") from exc
            if encoded != label:
                labels[index] = encoded.lower()
    return ".".join(labels)


def normalize_regex(value: str) -> str:
    """Return a regex body without AdGuard or Clash delimiters."""

    value = _strip_quotes(value).strip()
    if value.startswith("/"):
        if len(value) > 1 and value.endswith("/"):
            value = value[1:-1]
        else:
            # A current upstream has four lines written as /pattern^ instead
            # of /pattern/.  Treat the final unescaped ^ as the accidental
            # AdGuard terminator and retain the meaningful leading anchor.
            value = value[1:]
            if value.endswith("^") and not value.endswith(r"\^"):
                value = value[:-1]
    if not value:
        raise RuleParseError("empty regular expression")
    try:
        re.compile(value)
    except re.error as exc:
        raise RuleParseError(f"invalid regular expression {value!r}: {exc}") from exc
    return value


def _add_domain_rule(rules: RuleSet, kind: str, value: str) -> None:
    domain = normalize_domain(value)
    if "*" in domain:
        rules.add("wildcard", domain)
    else:
        rules.add(kind, domain)


def _add_adguard_rule(rules: RuleSet, line: str) -> None:
    body = line[2:]
    # AdGuard options follow ^$, and the terminal ^ itself is not part of the
    # hostname.  Splitting at the first ^ also handles rules without options.
    body = body.split("^", 1)[0].strip()
    if not body:
        raise RuleParseError("empty AdGuard domain rule")
    _add_domain_rule(rules, "suffix", body)


def _add_clash_rule(rules: RuleSet, prefix: str, value: str) -> None:
    prefix = prefix.upper()
    value = _strip_quotes(value)
    if prefix == "DOMAIN-REGEX":
        rules.add("regex", normalize_regex(value))
        return
    if prefix == "DOMAIN-SUFFIX":
        _add_domain_rule(rules, "suffix", value)
        return
    if prefix == "DOMAIN":
        _add_domain_rule(rules, "exact", value)
        return
    raise RuleParseError(f"unsupported rule type {prefix!r}")


def parse_source(text: str, source_name: str = "source") -> ParsedSource:
    """Parse supported AdGuard, Clash, YAML payload, and plain-domain lines."""

    rules = RuleSet()
    unsupported: List[Tuple[int, str]] = []
    recognized = 0

    for line_number, original in enumerate(text.splitlines(), 1):
        line = original.strip().lstrip("\ufeff")
        if not line or line.startswith(("!", "#", ";", "//")):
            continue

        # YAML list items are common in rule-provider files.
        if line.startswith("-"):
            line = line[1:].strip()
        if line.startswith(("\"", "'")) and line.endswith(line[0]):
            line = _strip_quotes(line)

        structural_match = re.match(r"^([A-Za-z][A-Za-z0-9_-]*)\s*:", line)
        if structural_match and structural_match.group(1).lower() in STRUCTURAL_KEYS:
            continue

        try:
            clash_match = RULE_PREFIX_RE.match(line)
            if clash_match:
                _add_clash_rule(rules, clash_match.group(1), clash_match.group(2))
                recognized += 1
                continue
            if line.startswith("||"):
                _add_adguard_rule(rules, line)
                recognized += 1
                continue
            if line.startswith("/"):
                rules.add("regex", normalize_regex(line))
                recognized += 1
                continue

            # Minimal hosts-file support is useful for small community lists,
            # while refusing arbitrary multi-column input prevents accidental
            # ingestion of unrelated metadata.
            tokens = line.split()
            if len(tokens) == 2 and tokens[0] in {"0.0.0.0", "127.0.0.1", "::1"}:
                _add_domain_rule(rules, "suffix", tokens[1])
                recognized += 1
                continue
            if len(tokens) == 1:
                _add_domain_rule(rules, "suffix", tokens[0])
                recognized += 1
                continue
            raise RuleParseError("unrecognized rule syntax")
        except RuleParseError as exc:
            unsupported.append((line_number, f"{original!r}: {exc}"))

    if unsupported:
        details = "\n".join(f"  line {number}: {message}" for number, message in unsupported[:20])
        if len(unsupported) > 20:
            details += f"\n  ... and {len(unsupported) - 20} more"
        raise RuleParseError(f"{source_name} contains unsupported or invalid lines:\n{details}")
    if rules.count() == 0:
        raise RuleParseError(f"{source_name} produced no rules")
    return ParsedSource(rules=rules, recognized_lines=recognized)


def fetch_source(url: str, retries: int = 3) -> str:
    """Fetch one public source with bounded retries and a stable user agent."""

    request = Request(url, headers={"User-Agent": USER_AGENT})
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            with urlopen(request, timeout=30) as response:
                data = response.read()
            return data.decode("utf-8-sig")
        except (HTTPError, URLError, TimeoutError, UnicodeDecodeError) as exc:
            last_error = exc
            if attempt + 1 < retries:
                time.sleep(attempt + 1)
    raise FetchError(f"failed to fetch {url}: {last_error}")


def load_config(path: Path) -> List[Mapping[str, str]]:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuleParseError(f"cannot read configuration {path}: {exc}") from exc
    sources = config.get("sources") if isinstance(config, dict) else None
    if not isinstance(sources, list) or not sources:
        raise RuleParseError("configuration must contain a non-empty sources list")
    seen: Set[str] = set()
    validated: List[Mapping[str, str]] = []
    for source in sources:
        if not isinstance(source, dict):
            raise RuleParseError("each source must be an object")
        source_id = str(source.get("id", "")).strip()
        url = str(source.get("url", "")).strip()
        if not source_id or source_id in seen:
            raise RuleParseError(f"source id is missing or duplicated: {source_id!r}")
        if not url.startswith("https://"):
            raise RuleParseError(f"source {source_id!r} must use an HTTPS URL")
        seen.add(source_id)
        validated.append(source)
    return validated


def wildcard_to_regex(pattern: str) -> str:
    escaped_parts = [re.escape(part) for part in pattern.split("*")]
    return "^" + ".*".join(escaped_parts) + "$"


def _source_comments(source_records: Sequence[Mapping[str, object]], prefix: str) -> List[str]:
    lines = [
        f"{prefix} Generated by scripts/sync_rules.py; do not edit this file directly.",
        f"{prefix} Edit sources.json and rerun the generator to change inputs.",
        f"{prefix} Required upstream sources (content SHA-256):",
    ]
    for source in source_records:
        lines.append(
            f"{prefix} - {source['name']} | {source['url']} | sha256={source['sha256']}"
        )
    return lines


def _adh_regex(pattern: str) -> str:
    return "/" + pattern.replace("/", r"\/") + "/"


def render_adh(rules: RuleSet, source_records: Sequence[Mapping[str, object]]) -> str:
    effective = rules.effective()
    lines = ["! PCDN block list for AdGuard Home"]
    lines.extend(_source_comments(source_records, "!"))
    lines.append("")
    lines.append("! Domain and exact-domain rules")
    for domain in sorted(effective["suffix"] | effective["exact"]):
        lines.append(f"||{domain}^")
    if effective["wildcard"]:
        lines.append("")
        lines.append("! Host wildcard rules")
        for pattern in sorted(effective["wildcard"]):
            lines.append(f"||{pattern}^")
    if effective["regex"]:
        lines.append("")
        lines.append("! Regular expression rules")
        for pattern in sorted(effective["regex"]):
            # A literal slash in a regex body must be escaped for AdGuard's
            # slash-delimited regex syntax.
            lines.append(_adh_regex(pattern))
    return "\n".join(lines) + "\n"


def render_clash(rules: RuleSet, source_records: Sequence[Mapping[str, object]]) -> str:
    effective = rules.effective()
    lines = ["# PCDN block list for Clash/Mihomo", "# behavior: domain"]
    lines.extend(_source_comments(source_records, "#"))
    lines.append("")
    lines.append("payload:")
    for domain in sorted(effective["suffix"]):
        lines.append(f"  - DOMAIN-SUFFIX,{domain}")
    for domain in sorted(effective["exact"]):
        lines.append(f"  - DOMAIN,{domain}")
    for pattern in sorted(effective["wildcard"]):
        lines.append(f"  - DOMAIN-REGEX,{wildcard_to_regex(pattern)}")
    for pattern in sorted(effective["regex"]):
        lines.append(f"  - DOMAIN-REGEX,{pattern}")
    return "\n".join(lines) + "\n"


def render_lock(source_records: Sequence[Mapping[str, object]], rules: RuleSet) -> str:
    effective = rules.effective()
    payload = {
        "generator": "scripts/sync_rules.py",
        "sources": list(source_records),
        "rules": {key: len(value) for key, value in effective.items()},
        "total_rules": sum(len(value) for value in effective.values()),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def build_outputs(config_path: Path) -> Dict[Path, str]:
    sources = load_config(config_path)
    combined = RuleSet()
    source_records: List[Mapping[str, object]] = []

    for source in sources:
        source_id = str(source["id"])
        url = str(source["url"])
        text = fetch_source(url)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        parsed = parse_source(text, source_id)
        combined.merge(parsed.rules)
        source_records.append(
            {
                "id": source_id,
                "name": str(source.get("name", source_id)),
                "url": url,
                "format": str(source.get("format", "auto")),
                "sha256": digest,
                "recognized_lines": parsed.recognized_lines,
                "unique_rules": parsed.rules.count(),
            }
        )
        print(
            f"{source_id}: {parsed.rules.count()} unique rules, "
            f"sha256={digest}"
        )

    if combined.count() == 0:
        raise RuleParseError("all sources combined produced no rules")
    return {
        OUTPUT_FILES["adh"]: render_adh(combined, source_records),
        OUTPUT_FILES["clash"]: render_clash(combined, source_records),
        OUTPUT_FILES["lock"]: render_lock(source_records, combined),
    }


def write_outputs(outputs: Mapping[Path, str]) -> None:
    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_text(content, encoding="utf-8", newline="\n")
        temporary.replace(path)
        print(f"wrote {path.relative_to(ROOT)}")


def check_outputs(outputs: Mapping[Path, str]) -> bool:
    clean = True
    for path, expected in outputs.items():
        actual = path.read_text(encoding="utf-8") if path.exists() else ""
        if actual == expected:
            continue
        clean = False
        print(f"{path.relative_to(ROOT)} is stale or missing", file=sys.stderr)
        diff = difflib.unified_diff(
            actual.splitlines(),
            expected.splitlines(),
            fromfile=str(path),
            tofile=f"{path} (expected)",
            lineterm="",
        )
        print("\n".join(diff), file=sys.stderr)
    return clean


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path, default=DEFAULT_CONFIG, help="source configuration JSON"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="fetch and render in memory, then fail if committed outputs are stale",
    )
    args = parser.parse_args(argv)
    try:
        outputs = build_outputs(args.config.resolve())
        if args.check:
            return 0 if check_outputs(outputs) else 1
        write_outputs(outputs)
        return 0
    except (FetchError, OSError, RuleParseError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
