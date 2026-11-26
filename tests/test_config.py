"""Tests for key resolution and storage."""

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sonargaze import config

from .helpers import keyring_stub


class ConfigTestBase(unittest.TestCase):
    """Every test runs against a throwaway config dir and a clean environment."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.env = mock.patch.dict(
            os.environ,
            {"SONARGAZE_CONFIG_DIR": str(self.dir / "config")},
            clear=False,
        )
        self.env.start()
        os.environ.pop("SONARGAZE_API_KEY", None)
        os.environ.pop("SHODAN_API_KEY", None)
        self._cwd = str(Path.cwd())
        os.chdir(self.dir)

    def tearDown(self):
        os.chdir(self._cwd)
        self.env.stop()
        self._tmp.cleanup()


class EnvFileTests(ConfigTestBase):
    def test_parse_env_file_handles_comments_quotes_and_export(self):
        target = self.dir / ".env"
        target.write_text(
            "# comment\n"
            "SHODAN_API_KEY=abc123\n"
            'export SONARGAZE_API_KEY = "quoted value"\n'
            "EMPTY=\n"
            "not a pair\n",
            encoding="utf-8",
        )
        values = config.parse_env_file(target)
        self.assertEqual(values["SHODAN_API_KEY"], "abc123")
        self.assertEqual(values["SONARGAZE_API_KEY"], "quoted value")
        self.assertEqual(values["EMPTY"], "")
        self.assertNotIn("not a pair", values)

    def test_missing_env_file_is_empty(self):
        self.assertEqual(config.parse_env_file(self.dir / "nope.env"), {})


class ResolutionTests(ConfigTestBase):
    def test_explicit_key_wins(self):
        os.environ["SHODAN_API_KEY"] = "from-env"
        with keyring_stub(fail=True):
            self.assertEqual(config.find_api_key("explicit"), "explicit")

    def test_environment_beats_stored_key(self):
        os.environ["SONARGAZE_API_KEY"] = "dedicated"
        os.environ["SHODAN_API_KEY"] = "legacy"
        with keyring_stub(fail=True):
            self.assertEqual(config.find_api_key(), "dedicated")

    def test_keyring_used_when_no_environment(self):
        with keyring_stub({config.KEYRING_USER: "from-keyring"}):
            self.assertEqual(config.find_api_key(), "from-keyring")

    def test_dotenv_file_is_the_last_resort(self):
        (self.dir / ".env").write_text("SHODAN_API_KEY=from-dotenv\n", encoding="utf-8")
        with keyring_stub(fail=True):
            self.assertEqual(config.find_api_key(), "from-dotenv")

    def test_require_api_key_explains_how_to_fix_it(self):
        with keyring_stub(fail=True), self.assertRaises(config.ConfigError) as caught:
            config.require_api_key()
        message = str(caught.exception)
        self.assertIn("key set", message)
        self.assertIn("SHODAN_API_KEY", message)


class StorageTests(ConfigTestBase):
    def test_save_writes_a_private_file(self):
        with keyring_stub(fail=True):
            where = config.save_api_key("abc123456789", prefer_keyring=True)
        path = self.dir / "config" / ".env"
        self.assertEqual(where, str(path))
        self.assertIn("SHODAN_API_KEY=abc123456789", path.read_text(encoding="utf-8"))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_save_uses_keyring_when_asked(self):
        with keyring_stub() as stored:
            where = config.save_api_key("vaulted", prefer_keyring=True)
        self.assertIn("keyring", where)
        self.assertEqual(stored[config.KEYRING_USER], "vaulted")

    def test_save_refuses_empty(self):
        with keyring_stub(fail=True), self.assertRaises(config.ConfigError):
            config.save_api_key("  ")

    def test_clear_removes_the_file(self):
        with keyring_stub(fail=True):
            config.save_api_key("abc123456789", prefer_keyring=False)
            cleared = config.clear_api_key()
            self.assertTrue(cleared)
            self.assertIsNone(config.find_api_key())


class MaskTests(unittest.TestCase):
    def test_mask_never_reveals_the_key(self):
        masked = config.mask_key("abcdefghijklmnop")
        self.assertNotIn("abcdefghij", masked)
        self.assertTrue(masked.startswith(config.MASK))
        self.assertIn("mnop", masked)
        self.assertEqual(config.mask_key(None), "not configured")


if __name__ == "__main__":
    unittest.main()
