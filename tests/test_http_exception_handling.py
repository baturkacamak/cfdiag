#!/usr/bin/env python3
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import cfdiag.network


class TestHttpExceptionHandling(unittest.TestCase):
    def setUp(self):
        # Patch logger so we can inspect add_html_step calls without real I/O.
        self.logger = MagicMock()
        self.logger.add_html_step = MagicMock()
        self.get_logger_patcher = patch("cfdiag.network.get_logger", return_value=self.logger)
        self.get_logger_patcher.start()

    def tearDown(self):
        self.get_logger_patcher.stop()

    @patch("cfdiag.network.run_command")
    def test_timeout_error_is_labeled_and_nonzero_status(self, mock_run):
        """
        TEST CASE 1: Timeout handling (ConnectTimeout)
        When curl times out, status must be non-zero and report should contain ConnectTimeout.
        """
        mock_run.return_value = (
            28,
            "curl: (28) Operation timed out after 10000 milliseconds\n",
        )

        result, status, waf, metrics = cfdiag.network.step_http("example.com")

        # Function should complete without crashing.
        self.assertIn(result, ("TIMEOUT", "ERROR"))
        # Status code should not be the old '0' default.
        self.assertNotEqual(status, 0)

        # Metrics object must not be empty and should contain expected keys.
        self.assertNotEqual(metrics, {})
        for key in ("connect", "start", "total", "ttfb"):
            self.assertIn(key, metrics)

        # Ensure the HTML/report text mentions ConnectTimeout.
        added = self.logger.add_html_step.call_args[0]
        details = added[2]
        self.assertIn("ERROR (ConnectTimeout)", details)

    @patch("cfdiag.network.run_command")
    def test_connection_error_is_labeled(self, mock_run):
        """
        TEST CASE 2: Connection refused handling (ConnectionError)
        """
        mock_run.return_value = (
            7,
            "curl: (7) Failed to connect to host: Connection refused\n",
        )

        result, status, waf, metrics = cfdiag.network.step_http("example.com")

        self.assertEqual(result, "ERROR")
        self.assertNotEqual(status, 0)

        added = self.logger.add_html_step.call_args[0]
        details = added[2]
        self.assertIn("ERROR (ConnectionError)", details)
        self.assertNotEqual(metrics, {})

    @patch("cfdiag.network.run_command")
    def test_metrics_dictionary_integrity_on_error(self, mock_run):
        """
        TEST CASE 3: Metrics object integrity (template crash prevention)
        Even when an error occurs, metrics must contain default keys.
        """
        mock_run.return_value = (1, "Some unexpected error")

        _, _, _, metrics = cfdiag.network.step_http("example.com")

        self.assertNotEqual(metrics, {})
        for key in ("connect", "start", "total", "ttfb"):
            self.assertIn(key, metrics)

    @patch("cfdiag.network.run_command")
    def test_ssl_error_is_labeled(self, mock_run):
        """
        TEST CASE 4: SSL error labeling (SSLError)
        """
        mock_run.return_value = (
            60,
            "curl: (60) SSL certificate problem: self signed certificate\n",
        )

        result, status, waf, metrics = cfdiag.network.step_http("example.com")

        self.assertEqual(result, "ERROR")
        self.assertNotEqual(status, 0)

        added = self.logger.add_html_step.call_args[0]
        details = added[2]
        self.assertIn("ERROR (SSLError)", details)

    @patch("cfdiag.network.run_command")
    def test_status_zero_is_never_returned_on_error(self, mock_run):
        """
        TEST CASE 5: Status '0' regression test
        Ensure that in any error scenario status is never equal to integer 0.
        """
        mock_run.return_value = (2, "curl: (2) Unknown error occurred")

        result, status, waf, metrics = cfdiag.network.step_http("example.com")

        self.assertEqual(result, "ERROR")
        self.assertNotEqual(status, 0)


if __name__ == "__main__":
    unittest.main()

