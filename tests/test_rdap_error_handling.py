#!/usr/bin/env python3
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import cfdiag.network


class TestRDAPErrorHandling(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock()
        self.logger.log_file = MagicMock()
        self.logger.add_html_step = MagicMock()
        self.get_logger_patcher = patch("cfdiag.network.get_logger", return_value=self.logger)
        self.get_logger_patcher.start()
        
        # Mock print functions
        self.print_success_mock = MagicMock()
        self.print_warning_mock = MagicMock()
        self.print_subheader_mock = MagicMock()
        self.print_success_patcher = patch("cfdiag.network.print_success", self.print_success_mock)
        self.print_warning_patcher = patch("cfdiag.network.print_warning", self.print_warning_mock)
        self.print_subheader_patcher = patch("cfdiag.network.print_subheader", self.print_subheader_mock)
        self.print_success_patcher.start()
        self.print_warning_patcher.start()
        self.print_subheader_patcher.start()

    def tearDown(self):
        self.get_logger_patcher.stop()
        self.print_success_patcher.stop()
        self.print_warning_patcher.stop()
        self.print_subheader_patcher.stop()

    @patch("cfdiag.network.run_command")
    @patch("cfdiag.network.get_curl_flags")
    def test_api_error_404_429_handling(self, mock_get_flags, mock_run_command):
        """
        TEST CASE 1: API error management (404/500/429 status codes).
        When RDAP server returns error, it should be shown to user with meaningful message.
        """
        mock_get_flags.return_value = ""
        
        # Test 404 error
        mock_run_command.return_value = (0, '{"error": "Domain not found"}\nHTTP_CODE:404')
        cfdiag.network.step_domain_status("example.com")
        
        # Check that error message was logged
        added = self.logger.add_html_step.call_args[0]
        status = added[1]
        detail = added[2]
        
        self.assertEqual(status, "WARN", "404 error should result in WARN status")
        self.assertIn("Query Failed: 404", detail, "Should mention 'Query Failed: 404'")
        self.assertNotEqual(detail, "", "Detail should not be empty")
        self.print_warning_mock.assert_called()
        
        # Test 429 error
        mock_run_command.return_value = (0, '{"error": "Rate limited"}\nHTTP_CODE:429')
        cfdiag.network.step_domain_status("example.com")
        
        added = self.logger.add_html_step.call_args[0]
        detail = added[2]
        self.assertIn("429", detail, "Should mention 429 error")
        self.assertIn("Too Many Requests", detail, "Should mention rate limiting")

    @patch("cfdiag.network.run_command")
    @patch("cfdiag.network.get_curl_flags")
    def test_empty_json_response(self, mock_get_flags, mock_run_command):
        """
        TEST CASE 2: Empty JSON/data response (Silent failure control).
        When server returns 200 OK but empty JSON, UI should not be empty.
        """
        mock_get_flags.return_value = ""
        
        # Test empty JSON object
        mock_run_command.return_value = (0, '{}\nHTTP_CODE:200')
        cfdiag.network.step_domain_status("example.com")
        
        added = self.logger.add_html_step.call_args[0]
        status = added[1]
        detail = added[2]
        
        # Should not be empty, should have meaningful message
        self.assertNotEqual(detail, "", "Detail should not be empty for empty JSON")
        self.assertNotEqual(detail.strip(), "", "Detail should not be just whitespace")
        # Should indicate no data available
        self.assertTrue(
            "No RDAP records found" in detail or "RDAP Data Not Available" in detail or "No status information" in detail,
            "Should indicate no data available"
        )
        
        # HTML step should have content (not empty div)
        self.assertIsNotNone(detail, "HTML step detail should not be None")

    @patch("cfdiag.network.run_command")
    @patch("cfdiag.network.get_curl_flags")
    def test_timeout_handling(self, mock_get_flags, mock_run_command):
        """
        TEST CASE 3: Timeout management.
        When RDAP server is too slow, program should timeout gracefully.
        """
        mock_get_flags.return_value = ""
        
        # Simulate timeout (curl exit code 28)
        mock_run_command.return_value = (28, "curl: (28) Operation timed out")
        cfdiag.network.step_domain_status("example.com")
        
        added = self.logger.add_html_step.call_args[0]
        status = added[1]
        detail = added[2]
        
        # Should handle timeout gracefully
        self.assertIn(status, ["WARN", "INFO"], "Timeout should result in WARN or INFO (not FAIL, RDAP is optional)")
        self.assertIn("Request Timed Out", detail or "", "Should mention 'Request Timed Out'")
        self.assertNotEqual(detail, "", "Detail should not be empty on timeout")
        
        # Should not crash
        self.print_warning_mock.assert_called()

    @patch("cfdiag.network.run_command")
    @patch("cfdiag.network.get_curl_flags")
    def test_successful_data_flow(self, mock_get_flags, mock_run_command):
        """
        TEST CASE 4: Successful data flow (Happy Path).
        When data comes correctly, system should parse and display it properly.
        """
        mock_get_flags.return_value = ""
        
        # Mock successful RDAP response
        successful_response = """{
            "handle": "DOM-123",
            "status": ["clientTransferProhibited", "serverDeleteProhibited"],
            "events": [
                {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2025-12-31T23:59:59Z"}
            ]
        }
HTTP_CODE:200"""
        
        mock_run_command.return_value = (0, successful_response)
        cfdiag.network.step_domain_status("example.com")
        
        added = self.logger.add_html_step.call_args[0]
        status = added[1]
        detail = added[2]
        
        # Should parse successfully
        self.assertEqual(status, "INFO", "Successful query should result in INFO status")
        self.assertIn("DOM-123", detail, "Should contain handle 'DOM-123'")
        self.assertIn("2025-12-31", detail, "Should contain expiration date")
        self.assertNotIn("error", detail.lower(), "Should not contain error message")
        self.print_success_mock.assert_called()

    @patch("cfdiag.network.run_command")
    @patch("cfdiag.network.get_curl_flags")
    def test_connection_error_handling(self, mock_get_flags, mock_run_command):
        """
        Additional test: Connection errors should be handled gracefully.
        """
        mock_get_flags.return_value = ""
        
        # Simulate connection refused (curl exit code 7)
        mock_run_command.return_value = (7, "curl: (7) Failed to connect to rdap.org")
        cfdiag.network.step_domain_status("example.com")
        
        added = self.logger.add_html_step.call_args[0]
        status = added[1]
        detail = added[2]
        
        self.assertIn(status, ["WARN", "INFO"], "Connection error should result in WARN or INFO")
        self.assertIn("Connection Error", detail or "", "Should mention connection error")
        self.assertNotEqual(detail, "", "Detail should not be empty")

    @patch("cfdiag.network.run_command")
    @patch("cfdiag.network.get_curl_flags")
    def test_invalid_json_response(self, mock_get_flags, mock_run_command):
        """
        Additional test: Invalid JSON should be handled gracefully.
        """
        mock_get_flags.return_value = ""
        
        # Mock invalid JSON response
        mock_run_command.return_value = (0, '{"invalid": json}\nHTTP_CODE:200')
        cfdiag.network.step_domain_status("example.com")
        
        added = self.logger.add_html_step.call_args[0]
        status = added[1]
        detail = added[2]
        
        self.assertEqual(status, "WARN", "Invalid JSON should result in WARN status")
        self.assertIn("Data parsing failed", detail or "", "Should mention parsing failure")
        self.assertNotEqual(detail, "", "Detail should not be empty")


if __name__ == "__main__":
    unittest.main()
