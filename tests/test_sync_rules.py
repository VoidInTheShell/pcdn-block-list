import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import sync_rules  # noqa: E402


class SyncRulesTests(unittest.TestCase):
    def test_parses_mixed_adguard_clash_yaml_and_plain_domains(self):
        parsed = sync_rules.parse_source(
            """
            ! comment
            ||example.com^
            ||stun*.example.net^
            /.*pcdn.*\\.example\\.org/
            DOMAIN-SUFFIX,clash.example
            - DOMAIN,exact.example
            - DOMAIN-REGEX,^p2p-[0-9]+\\.example\\.com$
            plain.example
            payload:
            """,
            "fixture",
        )

        self.assertIn("example.com", parsed.rules.suffix)
        self.assertIn("clash.example", parsed.rules.suffix)
        self.assertIn("exact.example", parsed.rules.exact)
        self.assertIn("stun*.example.net", parsed.rules.wildcard)
        self.assertIn(".*pcdn.*\\.example\\.org", parsed.rules.regex)
        self.assertIn("^p2p-[0-9]+\\.example\\.com$", parsed.rules.regex)
        self.assertIn("plain.example", parsed.rules.suffix)
        self.assertEqual(parsed.recognized_lines, 7)

    def test_repairs_known_unclosed_adguard_regex(self):
        parsed = sync_rules.parse_source(
            "/^.*pcdn.*biliapi\\.net^\n", "fixture"
        )
        self.assertIn("^.*pcdn.*biliapi\\.net", parsed.rules.regex)

    def test_wildcards_are_converted_to_clash_regex(self):
        self.assertEqual(
            sync_rules.wildcard_to_regex("*pcdn*.xxpkg.com"),
            r"^.*pcdn.*\.xxpkg\.com$",
        )

    def test_unsupported_lines_fail_closed(self):
        with self.assertRaises(sync_rules.RuleParseError):
            sync_rules.parse_source("@@||example.com^\n", "fixture")

    def test_redundant_exact_rule_is_removed_when_suffix_exists(self):
        rules = sync_rules.RuleSet()
        rules.add("suffix", "example.com")
        rules.add("exact", "example.com")
        self.assertEqual(rules.effective()["exact"], set())

    def test_rendered_formats_can_be_parsed_again(self):
        rules = sync_rules.RuleSet()
        rules.add("suffix", "example.com")
        rules.add("wildcard", "stun*.example.net")
        rules.add("regex", r"^p2p-[0-9]+\.example\.org$")
        sources = [
            {
                "name": "fixture",
                "url": "https://example.invalid/rules.txt",
                "sha256": "0" * 64,
            }
        ]

        adh = sync_rules.render_adh(rules, sources)
        clash = sync_rules.render_clash(rules, sources)
        self.assertGreater(sync_rules.parse_source(adh, "adh-output").rules.count(), 0)
        self.assertGreater(sync_rules.parse_source(clash, "clash-output").rules.count(), 0)


    def test_behavior_matches_classical_payload(self):
        rules = sync_rules.parse_source("DOMAIN-SUFFIX,example.com").rules
        output = sync_rules.render_clash(rules, [])
        self.assertIn("# behavior: classical\n# format: yaml", output)
        self.assertIn("DOMAIN-SUFFIX,example.com", output)

    def test_exact_domain_stays_exact_in_adguard_roundtrip(self):
        rules = sync_rules.parse_source("DOMAIN,only.example").rules
        output = sync_rules.render_adh(rules, [])
        self.assertIn("|only.example^", output)
        self.assertNotIn("||only.example^", output)
        parsed = sync_rules.parse_source(output, source_format="adguard").rules
        self.assertEqual(parsed.exact, {"only.example"})
        self.assertFalse(parsed.suffix)

    def test_adguard_wildcard_suffix_keeps_subdomain_coverage(self):
        rules = sync_rules.parse_source("||apd-*.example.net^", source_format="adguard").rules
        output = sync_rules.render_clash(rules, [])
        pattern = next(line.split("DOMAIN-REGEX,", 1)[1] for line in output.splitlines()
                       if "DOMAIN-REGEX," in line)
        for host in ["apd-demo.example.net", "child.apd-demo.example.net"]:
            self.assertRegex(host, pattern)
        for host in ["apd-demo.example.net.invalid", "other.example.net"]:
            self.assertIsNone(re.search(pattern, host))

    def test_adguard_exact_wildcard_is_not_suffix(self):
        parsed = sync_rules.parse_source("|apd-*.example.net^", source_format="adguard")
        self.assertEqual(parsed.rules.regex, {r"^apd\-.*\.example\.net$"})

    def test_modifiers_and_allow_rules_fail_closed(self):
        for line in ["||example.com^$dnstype=AAAA", "||example.com^$badfilter",
                     "||example.com^$client=one", "@@||example.com^", "||example.com^junk"]:
            with self.subTest(line=line), self.assertRaises(sync_rules.RuleParseError):
                sync_rules.parse_source(line, source_format="adguard")

    def test_declared_format_cannot_drift(self):
        for line, fmt in [("DOMAIN,example.com", "adguard"),
                          ("||example.com^", "domain-list"),
                          ("example.com", "clash"),
                          ("DOMAIN-SUFFIX,*.example.com", "clash")]:
            with self.subTest(line=line, fmt=fmt), self.assertRaises(sync_rules.RuleParseError):
                sync_rules.parse_source(line, source_format=fmt)

    def test_regex_validation_rejects_unknown_delimiters_and_re2_extensions(self):
        for line in ["/(", "/unterminated", "DOMAIN-REGEX,(",
                     r"DOMAIN-REGEX,(?=api)example", r"DOMAIN-REGEX,(x)\1",
                     r"DOMAIN-REGEX,(?<!api)example", r"DOMAIN-REGEX,a++",
                     r"DOMAIN-REGEX,(?#comment)example", r"DOMAIN-REGEX,(?ix)example",
                     r"DOMAIN-REGEX,example\Z", r"DOMAIN-REGEX,a{1001}"]:
            with self.subTest(line=line), self.assertRaises(sync_rules.RuleParseError):
                sync_rules.parse_source(line)

    def test_idn_normalizes_before_ascii_validation(self):
        parsed = sync_rules.parse_source("例子.测试", source_format="domain-list")
        self.assertEqual(parsed.rules.suffix, {"xn--fsqu00a.xn--0zwm56d"})


    def test_glob_recognition_is_generic_across_domains_and_anchors(self):
        import fnmatch
        import re
        for base in ("example.net", "other.invalid", "xn--fsqu00a.test"):
            for shape in ("*.", "edge-*.", "*-edge.", "pre*post.", "edge.*.", "*.*."):
                for suffix in (False, True):
                    pattern = shape + base
                    parsed = sync_rules.parse_source(("||" if suffix else "|") + pattern + "^", source_format="adguard")
                    line = next(line.strip()[2:] for line in sync_rules.render_clash(parsed.rules, []).splitlines() if "  - DOMAIN-REGEX," in line)
                    regex = line.split(",", 1)[1]
                    for replacement in ("alpha", "a.b", ""):
                        expanded = pattern.replace("*", replacement)
                        for host in (expanded, "child." + expanded, "a.b." + expanded, "control." + base):
                            if ".." in host or host.startswith("."):
                                continue
                            candidates = [host]
                            if suffix:
                                labels = host.split(".")
                                candidates.extend(".".join(labels[i:]) for i in range(1, len(labels)))
                            expected = any(fnmatch.fnmatchcase(candidate, pattern) for candidate in candidates)
                            with self.subTest(pattern=pattern, suffix=suffix, host=host):
                                self.assertEqual(bool(re.search(regex, host)), expected)


if __name__ == "__main__":
    unittest.main()
