#!/usr/bin/env python3
import unittest
from unittest.mock import patch, MagicMock
import cfdiag.core
import cfdiag.network
import cfdiag.reporting
import cfdiag.utils
import socket
import json
import os
import io
import sys

class TestCFDiag(unittest.TestCase):

    def setUp(self):
        self.log_patcher = patch('cfdiag.reporting.get_logger')
        self.mock_get_logger = self.log_patcher.start()
        
        self.mock_logger_instance = MagicMock()
        self.mock_logger_instance.html_data = {"domain": "test", "timestamp": "now", "steps": [], "summary": []}
        self.mock_logger_instance.save_html.return_value = True
        
        self.mock_get_logger.return_value = self.mock_logger_instance
        
        self.ctx_patcher = patch('cfdiag.utils.get_context', return_value={})
        self.mock_get_context = self.ctx_patcher.start()

    def tearDown(self):
        self.log_patcher.stop()
        self.ctx_patcher.stop()

    @patch('cfdiag.network.socket.create_connection')
    def test_internet_check(self, mock_conn):
        mock_conn.return_value.__enter__.return_value = MagicMock()
        self.assertTrue(cfdiag.network.check_internet_connection())

    @patch('cfdiag.network.socket.getaddrinfo')
    @patch('cfdiag.network.run_command')
    def test_dns_resolution(self, mock_run, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(socket.AF_INET, 0, 0, '', ('192.0.2.1', 443))]
        mock_run.return_value = (0, '{"isp": "Test"}')
        success, v4, v6 = cfdiag.network.step_dns("example.com")
        self.assertTrue(success)

    @patch('cfdiag.network.run_command')
    def test_ocsp_stapling(self, mock_run):
        mock_run.return_value = (0, "OCSP Response Status: successful")
        with patch('shutil.which', return_value='/usr/bin/openssl'):
            cfdiag.network.step_ocsp("example.com")

    @patch('cfdiag.network.check_internet_connection')
    @patch('cfdiag.network.step_dns')
    @patch('cfdiag.network.step_http')
    @patch('cfdiag.network.step_tcp')
    @patch('cfdiag.network.run_command')
    @patch('cfdiag.network.step_redirects')
    @patch('cfdiag.network.step_waf_evasion')
    @patch('cfdiag.network.step_ocsp')
    @patch('cfdiag.network.step_security_headers')
    def test_run_diagnostics_integration(self, mock_sec, mock_ocsp, mock_waf, mock_red, mock_run, mock_tcp, mock_http, mock_dns, mock_net):
        mock_net.return_value = True
        mock_dns.return_value = (True, ["1.1.1.1"], [])
        mock_http.return_value = ("SUCCESS", 200, False, {})
        mock_tcp.return_value = True
        mock_run.return_value = (0, "Mock Output")
        
        with patch('cfdiag.core.save_history', return_value={}), patch('cfdiag.core.save_metrics'):
            with patch('os.makedirs'), patch('cfdiag.reporting.FileLogger.save_to_file'):
                 # Need to patch FileLogger used in core
                 with patch('cfdiag.core.FileLogger', return_value=self.mock_logger_instance):
                     cfdiag.core.run_diagnostics_wrapper("example.com", None, None, True, False, False, {})
             
        self.mock_logger_instance.save_html.assert_called()

    def test_completion(self):
        capturedOutput = io.StringIO()
        sys.stdout = capturedOutput
        cfdiag.core.generate_completion("bash")
        sys.stdout = sys.__stdout__
        self.assertIn("complete -F _cfdiag cfdiag", capturedOutput.getvalue())

    def test_curl_flags(self):
        self.mock_get_context.return_value = {'ipv4': True}
        self.assertIn("-4", cfdiag.utils.get_curl_flags())

if __name__ == '__main__':
    unittest.main()