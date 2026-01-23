#!/usr/bin/env python3
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import cfdiag.core
import cfdiag.network


class Test522TimeoutLogic(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock()
        self.logger.log = MagicMock()
        self.logger.log_console = MagicMock()
        self.logger.log_file = MagicMock()
        self.get_logger_patcher = patch("cfdiag.core.get_logger", return_value=self.logger)
        self.get_logger_patcher.start()

    def tearDown(self):
        self.get_logger_patcher.stop()

    @patch("cfdiag.core.detect_cloudflare_usage")
    @patch("cfdiag.network.step_http")
    def test_cloudflare_user_timeout_shows_potential_522(self, mock_step_http, mock_detect_cf):
        """
        TEST CASE 1: Cloudflare user + Timeout (Valid 522 estimation).
        When target site uses Cloudflare AND request times out, report should show "Potential 522".
        """
        # Mock Cloudflare detection to return True
        mock_detect_cf.return_value = True
        
        # Mock HTTP step to return TIMEOUT status
        mock_step_http.return_value = ("TIMEOUT", -1, False, {"connect": 0.0, "start": 0.0, "total": 0.0, "ttfb": 0.0})
        
        # Mock DNS resolution success
        dns_res = (True, ["1.2.3.4"], [])
        
        # Mock other required parameters
        tcp_res = True
        cf_res = False
        mtu_res = True
        ssl_res = True
        cf_trace_res = (False, {})  # No CF trace, but detect_cloudflare_usage returns True
        origin_res = None
        alt_ports_res = (False, [])
        dnssec_status = "N/A"
        prop_status = "N/A"
        history_diff = None
        
        # Call generate_summary
        cfdiag.core.generate_summary(
            "example.com",
            dns_res,
            mock_step_http.return_value,
            tcp_res,
            cf_res,
            mtu_res,
            ssl_res,
            cf_trace_res,
            origin_res,
            alt_ports_res,
            dnssec_status,
            prop_status,
            history_diff,
        )
        
        # Check that "Potential 522" message was logged
        log_calls = [str(call) for call in self.logger.log.call_args_list]
        combined = "\n".join(log_calls)
        
        self.assertIn("Potential 522", combined, "Expected 'Potential 522' message for Cloudflare user with timeout")
        self.assertIn("Cloudflare Edge Network is reachable", combined, "Expected Cloudflare reachability message")

    @patch("cfdiag.core.detect_cloudflare_usage")
    @patch("cfdiag.network.step_http")
    def test_non_cloudflare_timeout_no_522(self, mock_step_http, mock_detect_cf):
        """
        TEST CASE 2: Non-Cloudflare site + Timeout (Generic timeout).
        When target site does NOT use Cloudflare, timeout should NOT mention "522".
        """
        # Mock Cloudflare detection to return False
        mock_detect_cf.return_value = False
        
        # Mock HTTP step to return TIMEOUT status
        mock_step_http.return_value = ("TIMEOUT", -1, False, {"connect": 0.0, "start": 0.0, "total": 0.0, "ttfb": 0.0})
        
        # Mock DNS resolution success
        dns_res = (True, ["8.8.8.8"], [])  # Google IP (not Cloudflare)
        
        # Mock other required parameters
        tcp_res = True
        cf_res = False
        mtu_res = True
        ssl_res = True
        cf_trace_res = (False, {})  # No CF trace
        origin_res = None
        alt_ports_res = (False, [])
        dnssec_status = "N/A"
        prop_status = "N/A"
        history_diff = None
        
        # Call generate_summary
        cfdiag.core.generate_summary(
            "example.com",
            dns_res,
            mock_step_http.return_value,
            tcp_res,
            cf_res,
            mtu_res,
            ssl_res,
            cf_trace_res,
            origin_res,
            alt_ports_res,
            dnssec_status,
            prop_status,
            history_diff,
        )
        
        # Check that "Potential 522" message was NOT logged
        log_calls = [str(call) for call in self.logger.log.call_args_list]
        combined = "\n".join(log_calls)
        
        self.assertNotIn("Potential 522", combined, "Should NOT mention 'Potential 522' for non-Cloudflare sites")
        # Should show generic timeout message (one of: "Connection Timed Out", "Request Timed Out", "Server Unreachable", or "HTTP Request Timed Out")
        timeout_message_found = (
            "Connection Timed Out" in combined or
            "Request Timed Out" in combined or
            "Server Unreachable" in combined or
            "HTTP Request Timed Out" in combined
        )
        self.assertTrue(timeout_message_found, "Should show generic timeout message (Connection Timed Out, Request Timed Out, Server Unreachable, or HTTP Request Timed Out)")
        self.assertNotIn("522", combined, "Should not mention '522' at all for non-Cloudflare sites")
        self.assertIn("NOT using Cloudflare", combined, "Should indicate Cloudflare is not in use")

    @patch("cfdiag.core.detect_cloudflare_usage")
    @patch("cfdiag.network.step_http")
    def test_cloudflare_connection_refused_no_522(self, mock_step_http, mock_detect_cf):
        """
        TEST CASE 3: Different error types (Connection Refused vs Timeout).
        When error is NOT timeout (e.g., Connection Refused), even Cloudflare users should NOT show "522".
        """
        # Mock Cloudflare detection to return True
        mock_detect_cf.return_value = True
        
        # Mock HTTP step to return ERROR status (Connection Refused, not timeout)
        mock_step_http.return_value = ("ERROR", -1, False, {"connect": 0.0, "start": 0.0, "total": 0.0, "ttfb": 0.0})
        
        # Mock DNS resolution success
        dns_res = (True, ["1.2.3.4"], [])
        
        # Mock other required parameters
        tcp_res = False  # TCP connection failed (connection refused)
        cf_res = False
        mtu_res = True
        ssl_res = True
        cf_trace_res = (False, {})
        origin_res = None
        alt_ports_res = (False, [])
        dnssec_status = "N/A"
        prop_status = "N/A"
        history_diff = None
        
        # Call generate_summary
        cfdiag.core.generate_summary(
            "example.com",
            dns_res,
            mock_step_http.return_value,
            tcp_res,
            cf_res,
            mtu_res,
            ssl_res,
            cf_trace_res,
            origin_res,
            alt_ports_res,
            dnssec_status,
            prop_status,
            history_diff,
        )
        
        # Check that "Potential 522" message was NOT logged (only for timeout)
        log_calls = [str(call) for call in self.logger.log.call_args_list]
        combined = "\n".join(log_calls)
        
        self.assertNotIn("Potential 522", combined, "Should NOT mention 'Potential 522' for non-timeout errors")
        self.assertNotIn("522", combined, "Should not mention '522' for connection refused errors")
        # Should show connection refused or port closed message
        connection_error_found = (
            "Connection Refused" in combined or
            "Port Closed" in combined or
            "Connection Error" in combined or
            "TCP connection failed" in combined
        )
        self.assertTrue(connection_error_found, "Should show connection refused or port closed message")
        # Should still detect Cloudflare usage
        self.assertIn("Cloudflare Edge Network is reachable", combined, "Should still detect Cloudflare usage")


if __name__ == "__main__":
    unittest.main()
