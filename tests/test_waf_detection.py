#!/usr/bin/env python3
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import cfdiag.network


class TestWAFDetection(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock()
        self.logger.add_html_step = MagicMock()
        self.get_logger_patcher = patch("cfdiag.network.get_logger", return_value=self.logger)
        self.get_logger_patcher.start()

    def tearDown(self):
        self.get_logger_patcher.stop()

    @patch("cfdiag.network.run_command")
    def test_generic_403_not_labeled_as_waf(self, mock_run):
        """
        TEST CASE 1: Generic 403 (parked/access denied) should not be labeled as confirmed WAF.
        """
        # Mock headers-only response (403)
        headers_output = """HTTP/1.1 403 Forbidden
Server: Apache
Content-Type: text/html

code=403;;connect=0.1;;start=0.2;;total=0.3"""
        
        # Mock body response (generic forbidden page)
        body_output = "<h1>Forbidden</h1><p>You don't have permission to access this resource.</p>"
        
        mock_run.side_effect = [
            (0, headers_output),  # Headers request
            (0, body_output),     # Body request
        ]
        
        result, status, waf, metrics = cfdiag.network.step_http("example.com")
        
        # WAF should not be detected (no signatures)
        self.assertFalse(waf)
        
        # Status line should indicate server config, not confirmed WAF
        # Find HTTP step (not Cache Analysis)
        http_step = None
        for call in self.logger.add_html_step.call_args_list:
            if call[0][0] == "HTTP":
                http_step = call[0]
                break
        self.assertIsNotNone(http_step, "HTTP step not found in HTML steps")
        details = http_step[2]
        self.assertIn("403 Forbidden (Server Config / Access Denied)", details)
        self.assertNotIn("WAF Detected", details)

    @patch("cfdiag.network.run_command")
    def test_header_based_waf_detection(self, mock_run):
        """
        TEST CASE 2: Header-based WAF detection (Cloudflare, Sucuri, AWS).
        """
        # Test Cloudflare
        headers_cf = """HTTP/1.1 403 Forbidden
Server: cloudflare
CF-Ray: 12345
Content-Type: text/html

code=403;;connect=0.1;;start=0.2;;total=0.3"""
        
        mock_run.side_effect = [
            (0, headers_cf),
            (0, ""),
        ]
        
        result, status, waf, metrics = cfdiag.network.step_http("example.com")
        
        self.assertTrue(waf)
        # Find HTTP step
        http_step = None
        for call in self.logger.add_html_step.call_args_list:
            if call[0][0] == "HTTP":
                http_step = call[0]
                break
        self.assertIsNotNone(http_step, "HTTP step not found")
        details = http_step[2]
        self.assertIn("WAF Detected: Cloudflare", details)
        
        # Test Sucuri
        headers_sucuri = """HTTP/1.1 403 Forbidden
X-Sucuri-ID: 12345
Content-Type: text/html

code=403;;connect=0.1;;start=0.2;;total=0.3"""
        
        mock_run.side_effect = [
            (0, headers_sucuri),
            (0, ""),
        ]
        
        result, status, waf, metrics = cfdiag.network.step_http("example.com")
        
        self.assertTrue(waf)
        added = self.logger.add_html_step.call_args[0]
        details = added[2]
        self.assertIn("WAF Detected: Sucuri", details)

    @patch("cfdiag.network.run_command")
    def test_body_based_waf_detection(self, mock_run):
        """
        TEST CASE 3: Body-based WAF detection (Captcha/Challenge pages).
        """
        # Cloudflare challenge page (200 OK but WAF challenge)
        headers_ok = """HTTP/1.1 200 OK
Server: nginx
Content-Type: text/html

code=200;;connect=0.1;;start=0.2;;total=0.3"""
        
        body_challenge = """<html>
<head><title>Attention Required! | Cloudflare</title></head>
<body>Please complete the security check to access...</body>
</html>"""
        
        mock_run.side_effect = [
            (0, headers_ok),
            (0, body_challenge),
        ]
        
        result, status, waf, metrics = cfdiag.network.step_http("example.com")
        
        self.assertTrue(waf)
        # Find HTTP step
        http_step = None
        for call in self.logger.add_html_step.call_args_list:
            if call[0][0] == "HTTP":
                http_step = call[0]
                break
        self.assertIsNotNone(http_step, "HTTP step not found")
        details = http_step[2]
        # Should detect Cloudflare from body even though status is 200
        self.assertIn("Cloudflare", details)

    @patch("cfdiag.network.run_command")
    def test_clean_response_no_waf(self, mock_run):
        """
        TEST CASE 4: Clean response (200 OK, no WAF signatures) should not report WAF.
        """
        headers_clean = """HTTP/1.1 200 OK
Server: Nginx
Content-Type: text/html

code=200;;connect=0.1;;start=0.2;;total=0.3"""
        
        body_clean = "<h1>Welcome to my blog</h1><p>Hello world</p>"
        
        mock_run.side_effect = [
            (0, headers_clean),
            (0, body_clean),
        ]
        
        result, status, waf, metrics = cfdiag.network.step_http("example.com")
        
        self.assertFalse(waf)
        # Find HTTP step
        http_step = None
        for call in self.logger.add_html_step.call_args_list:
            if call[0][0] == "HTTP":
                http_step = call[0]
                break
        self.assertIsNotNone(http_step, "HTTP step not found")
        details = http_step[2]
        self.assertNotIn("WAF", details)
        self.assertNotIn("Detected", details)
        self.assertNotIn("Forbidden", details)

    @patch("cfdiag.network.run_command")
    def test_unconfirmed_403_labeling(self, mock_run):
        """
        TEST CASE 5: Unconfirmed 403 (no WAF signatures) should be labeled as unconfirmed.
        """
        headers_403 = """HTTP/1.1 403 Forbidden
Server: Apache
Content-Type: text/html

code=403;;connect=0.1;;start=0.2;;total=0.3"""
        
        body_empty = ""
        
        mock_run.side_effect = [
            (0, headers_403),
            (0, body_empty),
        ]
        
        result, status, waf, metrics = cfdiag.network.step_http("example.com")
        
        self.assertFalse(waf)
        # Find HTTP step
        http_step = None
        for call in self.logger.add_html_step.call_args_list:
            if call[0][0] == "HTTP":
                http_step = call[0]
                break
        self.assertIsNotNone(http_step, "HTTP step not found")
        details = http_step[2]
        # Should indicate unconfirmed/server config, not specific WAF brand
        self.assertIn("403 Forbidden (Server Config / Access Denied)", details)
        self.assertNotIn("Cloudflare WAF Detected", details)
        self.assertNotIn("Sucuri", details)

    @patch("cfdiag.network.run_command")
    def test_waf_evasion_unconfirmed_labeling(self, mock_run):
        """
        Additional test: WAF evasion step should label unconfirmed cases correctly.
        """
        # Mock multiple user-agent tests, all returning 403 but no WAF signatures
        headers_403 = """HTTP/1.1 403 Forbidden
Server: Apache
Content-Type: text/html

code=403"""
        
        mock_run.side_effect = [
            (0, headers_403),  # Headers for UA 1
            (0, ""),           # Body for UA 1
            (0, headers_403),  # Headers for UA 2
            (0, ""),           # Body for UA 2
            (0, headers_403),  # Headers for UA 3
            (0, ""),           # Body for UA 3
        ]
        
        cfdiag.network.step_waf_evasion("example.com")
        
        # Check that logger was called with unconfirmed message
        log_calls = [str(call) for call in self.logger.log.call_args_list]
        combined = "\n".join(log_calls)
        
        # Should contain "Unconfirmed" or "Potential WAF"
        self.assertTrue(
            "Unconfirmed" in combined or "Potential WAF" in combined,
            f"Expected 'Unconfirmed' or 'Potential WAF' in log calls: {combined}"
        )
        
        # Should NOT contain specific WAF brand names
        self.assertNotIn("Cloudflare WAF Detected", combined)
        self.assertNotIn("Sucuri WAF Detected", combined)


if __name__ == "__main__":
    unittest.main()
