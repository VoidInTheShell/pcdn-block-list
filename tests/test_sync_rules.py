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


if __name__ == "__main__":
    unittest.main()
