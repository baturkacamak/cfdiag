#!/usr/bin/env python3
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import cfdiag.network


class TestDNSTraceParser(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock()
        self.logger.add_html_step = MagicMock()
        self.get_logger_patcher = patch("cfdiag.network.get_logger", return_value=self.logger)
        self.get_logger_patcher.start()
        
        # Mock print functions
        self.print_success_mock = MagicMock()
        self.print_warning_mock = MagicMock()
        self.print_fail_mock = MagicMock()
        self.print_success_patcher = patch("cfdiag.network.print_success", self.print_success_mock)
        self.print_warning_patcher = patch("cfdiag.network.print_warning", self.print_warning_mock)
        self.print_fail_patcher = patch("cfdiag.network.print_fail", self.print_fail_mock)
        self.print_success_patcher.start()
        self.print_warning_patcher.start()
        self.print_fail_patcher.start()

    def tearDown(self):
        self.get_logger_patcher.stop()
        self.print_success_patcher.stop()
        self.print_warning_patcher.stop()
        self.print_fail_patcher.stop()

    @patch("cfdiag.network.shutil.which")
    @patch("cfdiag.network.run_command")
    def test_harmless_warning_messages_pass(self, mock_run_command, mock_which):
        """
        TEST CASE 1: Harmless warning messages (False positive control).
        Operational warnings like 'Warning: multiple addresses' should not trigger WARN/FAIL status.
        """
        mock_which.return_value = "/usr/bin/dig"  # dig exists
        
        # Mock dig output with harmless warning
        stdout_output = """;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;example.com.                  IN      A

;; ANSWER SECTION:
example.com.           300     IN      A       192.0.79.134
example.com.           300     IN      A       192.0.79.135

;; Query time: 45 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Mon Jan 23 12:00:00 UTC 2026
;; MSG SIZE  rcvd: 89"""
        
        stderr_output = ";; Warning: example.com has multiple addresses; using 192.0.79.134"
        
        # run_command returns (exit_code, stdout_output)
        # stderr is typically merged, but we simulate it in stdout for this test
        mock_run_command.return_value = (0, stdout_output + "\n" + stderr_output)
        
        cfdiag.network.step_dns_trace("example.com")
        
        # Check that status is PASS (not WARN or FAIL)
        added = self.logger.add_html_step.call_args[0]
        status = added[1]
        
        self.assertEqual(status, "PASS", "Harmless warning should result in PASS status, not WARN/FAIL")
        
        # Verify success message was printed
        self.print_success_mock.assert_called_once()

    @patch("cfdiag.network.shutil.which")
    @patch("cfdiag.network.run_command")
    def test_real_dns_error_servfail(self, mock_run_command, mock_which):
        """
        TEST CASE 2: Real DNS error - SERVFAIL.
        When DNS server fails to respond, system should catch SERVFAIL.
        """
        mock_which.return_value = "/usr/bin/dig"
        
        # Mock SERVFAIL error
        output = """;; global options: +cmd
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 12345
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;example.com.                  IN      A

;; Query time: 123 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Mon Jan 23 12:00:00 UTC 2026
;; MSG SIZE  rcvd: 45"""
        
        mock_run_command.return_value = (0, output)
        
        cfdiag.network.step_dns_trace("example.com")
        
        # Check that status is FAIL
        added = self.logger.add_html_step.call_args[0]
        status = added[1]
        details = added[2]
        
        self.assertEqual(status, "FAIL", "SERVFAIL should result in FAIL status")
        self.assertIn("SERVFAIL", details, "SERVFAIL should be mentioned in output")
        
        # Verify fail message was printed
        self.print_fail_mock.assert_called_once()

    @patch("cfdiag.network.shutil.which")
    @patch("cfdiag.network.run_command")
    def test_real_dns_error_nxdomain(self, mock_run_command, mock_which):
        """
        TEST CASE 3: Real DNS error - NXDOMAIN.
        When domain does not exist, system should correctly respond with NXDOMAIN.
        """
        mock_which.return_value = "/usr/bin/dig"
        
        # Mock NXDOMAIN error
        output = """;; global options: +cmd
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 54321
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; QUESTION SECTION:
;nonexistent-domain-12345.com.  IN      A

;; AUTHORITY SECTION:
com.                    900     IN      SOA     a.gtld-servers.net. nstld.verisign-grs.com. 1234567890 1800 900 604800 86400

;; Query time: 45 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Mon Jan 23 12:00:00 UTC 2026
;; MSG SIZE  rcvd: 120"""
        
        mock_run_command.return_value = (0, output)
        
        cfdiag.network.step_dns_trace("nonexistent-domain-12345.com")
        
        # Check that status is FAIL
        added = self.logger.add_html_step.call_args[0]
        status = added[1]
        details = added[2]
        
        self.assertEqual(status, "FAIL", "NXDOMAIN should result in FAIL status")
        self.assertIn("NXDOMAIN", details, "NXDOMAIN should be mentioned in output")
        # Check that error message contains NXDOMAIN or domain not found
        error_msg_found = "nxdomain" in details.lower() or "domain not found" in details.lower()
        self.assertTrue(error_msg_found, "Should mention NXDOMAIN or domain not found")
        
        # Verify fail message was printed
        self.print_fail_mock.assert_called_once()

    @patch("cfdiag.network.shutil.which")
    @patch("cfdiag.network.run_command")
    def test_connection_timeout_error(self, mock_run_command, mock_which):
        """
        TEST CASE 4: Connection timeout (Timeout / Communications Error).
        When dig cannot reach server and times out, system should detect it.
        """
        mock_which.return_value = "/usr/bin/dig"
        
        # Mock connection timeout error
        output = """;; global options: +cmd
;; communications error to 1.2.3.4#53: connection timed out
;; communications error to 5.6.7.8#53: connection timed out
;; no servers could be reached"""
        
        mock_run_command.return_value = (1, output)  # Non-zero exit code
        
        cfdiag.network.step_dns_trace("example.com")
        
        # Check that status is FAIL
        added = self.logger.add_html_step.call_args[0]
        status = added[1]
        details = added[2]
        
        self.assertIn(status, ["FAIL", "WARN"], "Connection timeout should result in FAIL or WARN status")
        # Should detect either "connection timed out" or "communications error"
        timeout_detected = (
            "connection timed out" in details.lower() or
            "connection timeout" in details.lower() or
            "communications error" in details.lower()
        )
        self.assertTrue(timeout_detected, "Should detect 'connection timed out' or 'communications error'")
        
        # Verify fail message was printed
        self.print_fail_mock.assert_called_once()

    @patch("cfdiag.network.shutil.which")
    @patch("cfdiag.network.run_command")
    def test_clean_successful_query(self, mock_run_command, mock_which):
        """
        TEST CASE 5: Clean and successful query (Happy Path).
        Query with no errors or warnings should get PASS status.
        """
        mock_which.return_value = "/usr/bin/dig"
        
        # Mock clean successful query
        output = """;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;example.com.                  IN      A

;; ANSWER SECTION:
example.com.           300     IN      A       192.0.79.134

;; Query time: 25 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Mon Jan 23 12:00:00 UTC 2026
;; MSG SIZE  rcvd: 56"""
        
        mock_run_command.return_value = (0, output)
        
        cfdiag.network.step_dns_trace("example.com")
        
        # Check that status is PASS
        added = self.logger.add_html_step.call_args[0]
        status = added[1]
        
        self.assertEqual(status, "PASS", "Clean successful query should result in PASS status")
        
        # Verify success message was printed
        self.print_success_mock.assert_called_once()

    @patch("cfdiag.network.shutil.which")
    @patch("cfdiag.network.run_command")
    def test_refused_error(self, mock_run_command, mock_which):
        """
        Additional test: REFUSED error should be detected.
        """
        mock_which.return_value = "/usr/bin/dig"
        
        # Mock REFUSED error
        output = """;; global options: +cmd
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 12345
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;example.com.                  IN      A

;; Query time: 10 msec
;; SERVER: 1.2.3.4#53(1.2.3.4)
;; WHEN: Mon Jan 23 12:00:00 UTC 2026
;; MSG SIZE  rcvd: 45"""
        
        mock_run_command.return_value = (0, output)
        
        cfdiag.network.step_dns_trace("example.com")
        
        # Check that status is WARN (REFUSED is treated as WARN, not FAIL)
        added = self.logger.add_html_step.call_args[0]
        status = added[1]
        details = added[2]
        
        self.assertEqual(status, "WARN", "REFUSED should result in WARN status")
        self.assertIn("REFUSED", details, "REFUSED should be mentioned in output")
        
        # Verify warning message was printed
        self.print_warning_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
