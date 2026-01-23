#!/usr/bin/env python3
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import cfdiag.network


class TestHTMLOutputFiltering(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock()
        self.logger.log_file = MagicMock()
        self.logger.verbose = True
        self.logger.silent = False
        self.get_logger_patcher = patch("cfdiag.network.get_logger", return_value=self.logger)
        self.get_logger_patcher.start()

    def tearDown(self):
        self.get_logger_patcher.stop()

    @patch("cfdiag.network.subprocess.Popen")
    def test_html_output_from_remote_curl_is_filtered(self, mock_popen):
        """
        Test that HTML output from curl commands to remote domains is filtered out.
        """
        # Mock HTML response from remote domain
        html_output = """<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body><h1>Hello World</h1></body>
</html>"""
        
        # Mock subprocess
        mock_process = MagicMock()
        mock_process.stdout.readline.side_effect = [
            "<!DOCTYPE html>\n",
            "<html>\n",
            "<head><title>Test Page</title></head>\n",
            "<body><h1>Hello World</h1></body>\n",
            "</html>\n",
            "",  # Empty line to break loop
        ]
        mock_process.poll.return_value = 0
        mock_popen.return_value = mock_process
        
        # Run command with curl to remote domain
        command = "curl -s https://example.com"
        exit_code, output = cfdiag.network.run_command(command, log_output_to_file=True)
        
        # Check that HTML content was not logged
        log_calls = [str(call) for call in self.logger.log_file.call_args_list]
        combined = "\n".join(log_calls)
        
        # Should contain summary message about HTML being excluded
        self.assertIn("HTML Response from remote domain", combined, "Should mention HTML was excluded")
        self.assertIn("content excluded from report", combined, "Should mention content was excluded")
        
        # Should NOT contain the actual HTML content
        self.assertNotIn("<!DOCTYPE html>", combined, "Should not contain HTML DOCTYPE")
        self.assertNotIn("<html>", combined, "Should not contain HTML tags")
        self.assertNotIn("Hello World", combined, "Should not contain HTML body content")
        
        # But should still return the full output for processing
        self.assertIn("<!DOCTYPE html>", output, "Function should still return full output")

    @patch("cfdiag.network.subprocess.Popen")
    def test_non_html_output_is_logged(self, mock_popen):
        """
        Test that non-HTML output is still logged normally.
        """
        # Mock non-HTML output (DNS response)
        dns_output = """;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
example.com.           300     IN      A       192.0.79.134"""
        
        # Mock subprocess
        mock_process = MagicMock()
        mock_process.stdout.readline.side_effect = [
            ";; global options: +cmd\n",
            ";; Got answer:\n",
            ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345\n",
            "example.com.           300     IN      A       192.0.79.134\n",
            "",  # Empty line to break loop
        ]
        mock_process.poll.return_value = 0
        mock_popen.return_value = mock_process
        
        # Run command (dig, not curl to remote domain)
        command = "dig example.com +short"
        exit_code, output = cfdiag.network.run_command(command, log_output_to_file=True)
        
        # Check that non-HTML content was logged
        log_calls = [str(call) for call in self.logger.log_file.call_args_list]
        combined = "\n".join(log_calls)
        
        # Should contain the actual output
        self.assertIn("global options", combined, "Should contain DNS output")
        self.assertIn("NOERROR", combined, "Should contain DNS status")
        self.assertIn("192.0.79.134", combined, "Should contain DNS result")
        
        # Should NOT contain HTML exclusion message
        self.assertNotIn("HTML Response from remote domain", combined, "Should not mention HTML exclusion for non-HTML content")

    @patch("cfdiag.network.subprocess.Popen")
    def test_html_from_local_command_is_logged(self, mock_popen):
        """
        Test that HTML output from local commands (not remote curl) is still logged.
        """
        # Mock HTML output from local command
        html_output = """<!DOCTYPE html>
<html><body>Local HTML</body></html>"""
        
        # Mock subprocess
        mock_process = MagicMock()
        mock_process.stdout.readline.side_effect = [
            "<!DOCTYPE html>\n",
            "<html><body>Local HTML</body></html>\n",
            "",  # Empty line to break loop
        ]
        mock_process.poll.return_value = 0
        mock_popen.return_value = mock_process
        
        # Run local command (not curl to remote domain)
        command = "cat local.html"
        exit_code, output = cfdiag.network.run_command(command, log_output_to_file=True)
        
        # Check that HTML from local command was logged
        log_calls = [str(call) for call in self.logger.log_file.call_args_list]
        combined = "\n".join(log_calls)
        
        # Should contain the HTML content (local commands are not filtered)
        self.assertIn("<!DOCTYPE html>", combined, "Should contain HTML from local command")
        self.assertIn("Local HTML", combined, "Should contain HTML body from local command")
        
        # Should NOT contain HTML exclusion message
        self.assertNotIn("HTML Response from remote domain", combined, "Should not filter HTML from local commands")

    @patch("cfdiag.network.subprocess.Popen")
    def test_curl_to_localhost_is_not_filtered(self, mock_popen):
        """
        Test that curl to localhost is not filtered (not a remote domain).
        """
        # Mock HTML output from localhost
        html_output = """<!DOCTYPE html>
<html><body>Localhost HTML</body></html>"""
        
        # Mock subprocess
        mock_process = MagicMock()
        mock_process.stdout.readline.side_effect = [
            "<!DOCTYPE html>\n",
            "<html><body>Localhost HTML</body></html>\n",
            "",  # Empty line to break loop
        ]
        mock_process.poll.return_value = 0
        mock_popen.return_value = mock_process
        
        # Run curl to localhost (not remote domain)
        command = "curl -s http://localhost:8080"
        exit_code, output = cfdiag.network.run_command(command, log_output_to_file=True)
        
        # Check that localhost HTML was logged (localhost is not considered remote)
        log_calls = [str(call) for call in self.logger.log_file.call_args_list]
        combined = "\n".join(log_calls)
        
        # Should contain the HTML content
        self.assertIn("<!DOCTYPE html>", combined, "Should contain HTML from localhost")
        self.assertIn("Localhost HTML", combined, "Should contain HTML body from localhost")
        
        # Should NOT contain HTML exclusion message
        self.assertNotIn("HTML Response from remote domain", combined, "Should not filter HTML from localhost")

    @patch("cfdiag.network.subprocess.Popen")
    def test_json_output_from_remote_curl_is_logged(self, mock_popen):
        """
        Test that JSON output from remote curl is still logged (only HTML is filtered).
        """
        # Mock JSON output from remote domain
        json_output = """{"handle": "DOM-123", "status": ["clientTransferProhibited"]}"""
        
        # Mock subprocess
        mock_process = MagicMock()
        mock_process.stdout.readline.side_effect = [
            '{"handle": "DOM-123", "status": ["clientTransferProhibited"]}\n',
            "",  # Empty line to break loop
        ]
        mock_process.poll.return_value = 0
        mock_popen.return_value = mock_process
        
        # Run curl to remote domain
        command = "curl -s https://rdap.org/domain/example.com"
        exit_code, output = cfdiag.network.run_command(command, log_output_to_file=True)
        
        # Check that JSON content was logged (not HTML, so not filtered)
        log_calls = [str(call) for call in self.logger.log_file.call_args_list]
        combined = "\n".join(log_calls)
        
        # Should contain the JSON content
        self.assertIn("DOM-123", combined, "Should contain JSON content")
        self.assertIn("clientTransferProhibited", combined, "Should contain JSON data")
        
        # Should NOT contain HTML exclusion message
        self.assertNotIn("HTML Response from remote domain", combined, "Should not filter non-HTML content")


if __name__ == "__main__":
    unittest.main()
