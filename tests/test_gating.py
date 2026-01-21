import unittest
from unittest.mock import patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import cfdiag.core
import cfdiag.reporting

class TestGating(unittest.TestCase):
    def setUp(self):
        cfdiag.reporting.set_logger(MagicMock())

    @patch('cfdiag.core.step_dns')
    @patch('cfdiag.core.step_http')
    @patch('cfdiag.core.step_ssl')
    @patch('cfdiag.core.step_tcp')
    @patch('cfdiag.core.step_security_headers')
    @patch('cfdiag.core.step_traceroute')
    def test_dns_failure_skips_dependents(self, mock_tr, mock_headers, mock_tcp, mock_ssl, mock_http, mock_dns):
        # Setup DNS failure
        mock_dns.return_value = (False, [], [])
        
        # Run diagnostics
        cfdiag.core.run_diagnostics("example.com")
        
        # Assertions
        mock_dns.assert_called_once()
        mock_http.assert_not_called()
        mock_ssl.assert_not_called()
        mock_tcp.assert_not_called()
        mock_tr.assert_not_called()
        mock_headers.assert_not_called()

    @patch('cfdiag.core.step_dns')
    @patch('cfdiag.core.step_http')
    @patch('cfdiag.core.step_ssl')
    @patch('cfdiag.core.step_tcp')
    @patch('cfdiag.core.step_security_headers')
    def test_dns_success_runs_dependents(self, mock_headers, mock_tcp, mock_ssl, mock_http, mock_dns):
        # Setup DNS success
        mock_dns.return_value = (True, ['1.1.1.1'], [])
        mock_http.return_value = ("SUCCESS", 200, False, {})
        mock_tcp.return_value = True
        
        # Run diagnostics
        cfdiag.core.run_diagnostics("example.com")
        
        # Assertions
        mock_dns.assert_called_once()
        mock_http.assert_called_once()
        mock_tcp.assert_called_once()
        mock_headers.assert_called_once() # Dependent on HTTP OK (mocked 200)

    @patch('cfdiag.core.step_dns')
    @patch('cfdiag.core.step_http')
    @patch('cfdiag.core.step_security_headers')
    def test_http_failure_skips_headers(self, mock_headers, mock_http, mock_dns):
        # DNS Success
        mock_dns.return_value = (True, ['1.1.1.1'], [])
        # HTTP Failure (e.g. timeout or status 0)
        mock_http.return_value = ("FAIL", 0, False, {})
        
        # Run diagnostics
        cfdiag.core.run_diagnostics("example.com")
        
        # Assertions
        mock_http.assert_called_once()
        mock_headers.assert_not_called() # Should be skipped because http status is 0

if __name__ == '__main__':
    unittest.main()
