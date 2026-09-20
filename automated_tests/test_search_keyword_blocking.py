# test_search_keyword_blocking.py
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", "src"))

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

import vigilant_addon

class TestSearchKeywordBlocking(unittest.TestCase):

    def setUp(self):
        self.addon = vigilant_addon.VIGILANTAddon()

    @patch("vigilant_addon.get_blacklisted_keywords")
    @patch("vigilant_addon.load_proxy_config")
    @patch("vigilant_addon.log_request")
    @patch("vigilant_addon.update_device_activity")
    def test_google_banned_keyword_blocked(self, mock_update, mock_log, mock_config, mock_keywords):
        mock_keywords.return_value = ["pornhub", "marijuana", "gambling"]
        mock_config.return_value = {"block_harmful": True, "block_distracting": False}

        flow = MagicMock()
        flow.client_conn.peername = ("192.168.1.100", 12345)
        flow.request.pretty_host = "www.google.com"
        flow.request.path = "/search?q=pornhub&sca_esv=123"
        flow.request.method = "GET"
        flow.request.headers = {}
        flow.request.content = b""
        flow.request.pretty_url = "https://www.google.com/search?q=pornhub&sca_esv=123"

        self.addon.request(flow)

        # Assert response was populated with a 403 block page
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 403)
        mock_log.assert_called_with("192.168.1.100", "www.google.com", "/search?q=pornhub&sca_esv=123", "GET", "Harmful", True, [], "KEYWORD_MATCH")

    @patch("vigilant_addon.get_blacklisted_keywords")
    @patch("vigilant_addon.load_proxy_config")
    @patch("vigilant_addon.log_request")
    @patch("vigilant_addon.update_device_activity")
    def test_bing_banned_keyword_blocked(self, mock_update, mock_log, mock_config, mock_keywords):
        mock_keywords.return_value = ["pornhub", "marijuana", "gambling"]
        mock_config.return_value = {"block_harmful": True, "block_distracting": False}

        flow = MagicMock()
        flow.client_conn.peername = ("192.168.1.100", 12345)
        flow.request.pretty_host = "www.bing.com"
        flow.request.path = "/search?q=gambling&form=QBLH"
        flow.request.method = "GET"
        flow.request.headers = {}
        flow.request.content = b""
        flow.request.pretty_url = "https://www.bing.com/search?q=gambling&form=QBLH"

        self.addon.request(flow)

        # Assert response was populated with a 403 block page
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 403)
        mock_log.assert_called_with("192.168.1.100", "www.bing.com", "/search?q=gambling&form=QBLH", "GET", "Harmful", True, [], "KEYWORD_MATCH")

    @patch("vigilant_addon.get_blacklisted_keywords")
    @patch("vigilant_addon.load_proxy_config")
    @patch("vigilant_addon.log_request")
    @patch("vigilant_addon.update_device_activity")
    def test_google_clean_search_allowed(self, mock_update, mock_log, mock_config, mock_keywords):
        mock_keywords.return_value = ["pornhub", "marijuana", "gambling"]
        mock_config.return_value = {"block_harmful": True, "block_distracting": False}

        flow = MagicMock()
        flow.client_conn.peername = ("192.168.1.100", 12345)
        flow.request.pretty_host = "www.google.com"
        flow.request.path = "/search?q=calculus+lecture"
        flow.request.method = "GET"
        flow.request.headers = {}
        flow.request.content = b""
        flow.request.pretty_url = "https://www.google.com/search?q=calculus+lecture"
        flow.response = None

        self.addon.request(flow)

        # Clean search should not trigger 403 block
        self.assertIsNone(flow.response)

if __name__ == "__main__":
    unittest.main()
