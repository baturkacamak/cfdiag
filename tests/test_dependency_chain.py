#!/usr/bin/env python3
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import cfdiag.core


class TestDependencyChain(unittest.TestCase):
    def setUp(self):
        # Patch logger to avoid actual file/console I/O
        self.logger = MagicMock()
        self.logger.html_data = {"domain": "", "timestamp": "", "steps": [], "summary": []}

        self.patches = [
            patch("cfdiag.core.get_logger", return_value=self.logger),
            # patch("cfdiag.core.save_history", return_value={}),  # Removed in v3.12.8
            # patch("cfdiag.core.save_metrics"),                   # Removed in v3.12.8
            patch("cfdiag.core.step_blacklist"),
            patch("cfdiag.core.step_dns_trace"),
            patch("cfdiag.core.step_propagation", return_value="N/A"),
            patch("cfdiag.core.step_dnssec", return_value="DISABLED"),
            patch("cfdiag.core.step_domain_status"),
            patch("cfdiag.core.step_traceroute"),
            patch("cfdiag.core.step_cf_forced", return_value=True),
            patch("cfdiag.core.step_cf_trace", return_value=(False, {})),
            patch("cfdiag.core.step_alt_ports", return_value=(False, [])),
            # patch("cfdiag.core.step_redirects"), # Removed
            patch("cfdiag.core.step_waf_evasion"),
            patch("cfdiag.core.step_speed"),
            # patch("cfdiag.core.step_dns_benchmark"), # Removed
            patch("cfdiag.core.step_ocsp"),
            patch("cfdiag.core.step_websocket"),
            patch("cfdiag.core.step_audit"),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    @patch("cfdiag.core.step_mtu")
    @patch("cfdiag.core.step_ssl")
    @patch("cfdiag.core.step_http")
    @patch("cfdiag.core.step_tcp")
    @patch("cfdiag.core.step_dns")
    def test_tcp_failure_skips_ssl_http_mtu(self, mock_dns, mock_tcp, mock_http, mock_ssl, mock_mtu):
        """
        TEST CASE 1: TCP failure should prevent SSL/HTTP/MTU from running and mark them as SKIPPED.
        """
        # DNS succeeds with at least one IP
        mock_dns.return_value = (True, ["1.2.3.4"], [])
        # TCP connectivity fails
        mock_tcp.return_value = False

        result = cfdiag.core.run_diagnostics("example.com")

        mock_tcp.assert_called_once()
        mock_http.assert_not_called()
        mock_ssl.assert_not_called()
        mock_mtu.assert_not_called()

        self.assertEqual(result["http"], "SKIPPED (No TCP Connection)")
        self.assertEqual(result["ssl"], "SKIPPED (No TCP Connection)")
        self.assertEqual(result["mtu"], "SKIPPED (No TCP Connection)")

    @patch("cfdiag.core.step_mtu", return_value=True)
    @patch("cfdiag.core.step_ssl", return_value=True)
    @patch("cfdiag.core.step_http", return_value=("SUCCESS", 200, False, {}))
    @patch("cfdiag.core.step_tcp", return_value=True)
    @patch("cfdiag.core.step_dns")
    def test_tcp_success_runs_ssl_http_mtu(self, mock_dns, mock_tcp, mock_http, mock_ssl, mock_mtu):
        """
        TEST CASE 2: When TCP is successful, SSL/HTTP/MTU must be executed.
        """
        mock_dns.return_value = (True, ["1.2.3.4"], [])

        result = cfdiag.core.run_diagnostics("example.com")

        mock_tcp.assert_called_once()
        mock_http.assert_called_once()
        mock_ssl.assert_called_once()
        mock_mtu.assert_called_once()

        self.assertNotIn("SKIPPED", result["http"])
        self.assertNotEqual(result["ssl"], "SKIPPED (No TCP Connection)")
        self.assertNotEqual(result["mtu"], "SKIPPED (No TCP Connection)")

    @patch("cfdiag.core.step_mtu")
    @patch("cfdiag.core.step_ssl")
    @patch("cfdiag.core.step_http")
    @patch("cfdiag.core.step_tcp")
    @patch("cfdiag.core.step_dns")
    @patch("cfdiag.core.probe_dns")
    def test_dns_failure_stops_before_tcp_and_others(self, mock_probe_dns, mock_dns, mock_tcp, mock_http, mock_ssl, mock_mtu):
        """
        TEST CASE 3: When DNS fails, TCP and all dependent checks must not be executed.
        """
        # probe_dns failure simulation
        mock_probe_dns.return_value = {"error": "NXDOMAIN", "records": {"A": [], "AAAA": []}}
        mock_dns.return_value = (False, [], []) # This return value is likely ignored by run_diagnostics logic which uses probe_dns, but keeping for safety if step_dns is used for something else.

        result = cfdiag.core.run_diagnostics("example.com")

        mock_tcp.assert_not_called()
        mock_http.assert_not_called()
        mock_ssl.assert_not_called()
        mock_mtu.assert_not_called()

        self.assertEqual(result["dns"], "FAIL")
        # HTTP / SSL / MTU should be in a non-success state but not marked as TCP-related skip.
        self.assertIn(result["http"], ("SKIPPED", "SKIPPED (DNS failure)"))

    @patch("cfdiag.core.step_mtu")
    @patch("cfdiag.core.step_ssl")
    @patch("cfdiag.core.step_http")
    @patch("cfdiag.core.step_tcp")
    @patch("cfdiag.core.step_dns")
    def test_report_contains_explicit_tcp_skip_reason(self, mock_dns, mock_tcp, mock_http, mock_ssl, mock_mtu):
        """
        TEST CASE 4: Result object should clearly state the TCP skip reason for SSL/HTTP/MTU.
        """
        mock_dns.return_value = (True, ["1.2.3.4"], [])
        mock_tcp.return_value = False

        result = cfdiag.core.run_diagnostics("example.com")

        # Verify that the structured result clearly exposes the skip reason.
        self.assertEqual(result["http"], "SKIPPED (No TCP Connection)")
        self.assertEqual(result["ssl"], "SKIPPED (No TCP Connection)")
        self.assertEqual(result["mtu"], "SKIPPED (No TCP Connection)")

        # Skip reasons must not contain low-level TCP error strings.
        for value in (result["http"], result["ssl"], result["mtu"]):
            self.assertNotIn("Connection Refused", value)
            self.assertNotIn("Timed out", value)


if __name__ == "__main__":
    unittest.main()

