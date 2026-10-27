import os
import unittest
from unittest.mock import patch
from browser_security import allowed_origins, browser_origin_allowed

class BrowserSecurityTests(unittest.TestCase):
    def test_defaults_allow_local_ui_but_not_remote_websites(self):
        with patch.dict(os.environ, {}, clear=True):
            origins = allowed_origins()
        self.assertTrue(browser_origin_allowed("http://127.0.0.1:8001", origins))
        self.assertTrue(browser_origin_allowed("http://localhost:3000", origins))
        self.assertFalse(browser_origin_allowed("https://attacker.example", origins))
        self.assertFalse(browser_origin_allowed("null", origins))
        self.assertTrue(browser_origin_allowed(None, origins))

    def test_explicit_configuration_and_wildcard_rejection(self):
        with patch.dict(os.environ, {"CORS_ORIGINS": "https://trusted.example"}):
            self.assertEqual(allowed_origins(), ["https://trusted.example"])
        for unsafe in ("*", "null", "http://localhost:3000, *"):
            with self.subTest(unsafe=unsafe), patch.dict(os.environ, {"CORS_ORIGINS": unsafe}):
                with self.assertRaises(RuntimeError):
                    allowed_origins()

if __name__ == "__main__":
    unittest.main()
