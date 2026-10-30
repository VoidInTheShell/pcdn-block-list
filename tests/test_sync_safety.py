import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sync_rules


class SyncSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "sources.json"
        self.source = {"id": "one", "name": "one", "url": "https://example.invalid/one", "format": "domain-list"}
        self.config.write_text(json.dumps({"version": 1, "sources": [self.source]}))

    def publish(self, text="one.example\ntwo.example\n"):
        with patch.object(sync_rules, "fetch_source", return_value=text) as fetch:
            output = sync_rules.build_outputs(self.config)
        fetch.assert_called_once()
        sync_rules.write_outputs(output)

    def bytes(self):
        return {p.relative_to(self.root).as_posix(): p.read_bytes()
                for p in self.root.rglob("*") if p.is_file()}

    def test_locked_replay_never_refetches_even_when_upstream_changes(self):
        self.publish()
        before = self.bytes()
        with patch.object(sync_rules, "fetch_source", side_effect=AssertionError("network forbidden")):
            self.assertTrue(sync_rules.check_outputs(sync_rules.build_outputs(self.config, locked=True)))
            self.assertEqual(sync_rules.main(["--config", str(self.config), "--check"]), 0)
        self.assertEqual(self.bytes(), before)

    def test_locked_replay_preserves_crlf_bytes_and_checks_without_newline_translation(self):
        self.publish("one.example\r\ntwo.example\r\n")
        self.assertEqual((self.root / "inputs/one.txt").read_bytes(), b"one.example\r\ntwo.example\r\n")
        self.assertTrue(sync_rules.check_outputs(sync_rules.build_outputs(self.config, locked=True)))

    def test_fetch_preserves_utf8_bom_and_crlf_for_snapshot_hashing(self):
        import io
        raw = b"\xef\xbb\xbfone.example\r\ntwo.example\r\n"
        with patch.object(sync_rules, "urlopen", return_value=io.BytesIO(raw)):
            text = sync_rules.fetch_source(self.source["url"])
        self.assertEqual(text.encode("utf-8"), raw)
        self.publish(text)
        self.assertTrue(sync_rules.check_outputs(sync_rules.build_outputs(self.config, locked=True)))

    def test_corrupt_input_and_source_identity_change_fail_closed(self):
        self.publish()
        (self.root / "inputs/one.txt").write_text("tampered.example\n")
        with self.assertRaisesRegex(sync_rules.RuleParseError, "SHA-256"):
            sync_rules.build_outputs(self.config, locked=True)
        self.publish()
        self.source["url"] = "https://example.invalid/replaced"
        self.config.write_text(json.dumps({"sources": [self.source]}))
        with self.assertRaisesRegex(sync_rules.RuleParseError, "URL/format"):
            sync_rules.build_outputs(self.config, locked=True)

    def test_missing_snapshot_is_not_replaced_with_live_network(self):
        self.publish()
        (self.root / "inputs/one.txt").unlink()
        with patch.object(sync_rules, "fetch_source", side_effect=AssertionError("network forbidden")):
            with self.assertRaises(OSError):
                sync_rules.build_outputs(self.config, locked=True)

    def test_failed_fetch_and_large_count_change_do_not_advance_baseline(self):
        self.publish("".join(f"host{i}.example\n" for i in range(10)))
        before = self.bytes()
        with patch.object(sync_rules, "fetch_source", return_value="only.example\n"):
            with self.assertRaisesRegex(sync_rules.RuleParseError, "review required"):
                sync_rules.build_outputs(self.config)
        with patch.object(sync_rules, "fetch_source", side_effect=sync_rules.FetchError("failed")):
            with self.assertRaises(sync_rules.FetchError):
                sync_rules.build_outputs(self.config)
        self.assertEqual(self.bytes(), before)

    def test_atomic_publication_restores_old_outputs_on_late_failure(self):
        self.publish()
        before = self.bytes()
        with patch.object(sync_rules, "fetch_source", return_value="new.example\nother.example\n"):
            output = sync_rules.build_outputs(self.config)
        original = Path.replace
        def fail_lock(path, target):
            if Path(target).name == "sources.lock.json":
                raise OSError("simulated publication failure")
            return original(path, target)
        with patch.object(Path, "replace", fail_lock):
            with self.assertRaisesRegex(OSError, "publication failure"):
                sync_rules.write_outputs(output)
        self.assertEqual(self.bytes(), before)

    def test_source_ids_cannot_escape_input_directory(self):
        self.source["id"] = "../escape"
        self.config.write_text(json.dumps({"sources": [self.source]}))
        with self.assertRaises(sync_rules.RuleParseError):
            sync_rules.load_config(self.config)


if __name__ == "__main__":
    unittest.main()
