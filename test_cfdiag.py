#!/usr/bin/env python3
import unittest
from unittest.mock import patch, MagicMock, mock_open
import cfdiag
import socket
import json
import os

class TestCFDiag(unittest.TestCase):

    def setUp(self):
        self.log_patcher = patch('cfdiag.get_logger')
        self.mock_get_logger = self.log_patcher.start()
        
        self.mock_logger_instance = MagicMock()
        self.mock_logger_instance.html_data = {"domain": "test", "timestamp": "now", "steps": [], "summary": []}
        self.mock_logger_instance.save_html.return_value = True
        
        self.mock_get_logger.return_value = self.mock_logger_instance
        
        # Patch context to return empty dict by default
        self.ctx_patcher = patch('cfdiag.get_context', return_value={})
        self.mock_get_context = self.ctx_patcher.start()

    def tearDown(self):
        self.log_patcher.stop()
        self.ctx_patcher.stop()

    @patch('cfdiag.socket.create_connection')
    def test_internet_check(self, mock_conn):
        mock_conn.return_value.__enter__.return_value = MagicMock()
        self.assertTrue(cfdiag.check_internet_connection())

    @patch('cfdiag.socket.getaddrinfo')
    @patch('cfdiag.run_command')
    def test_dns_resolution(self, mock_run, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(socket.AF_INET, 0, 0, '', ('192.0.2.1', 443))]
        mock_run.return_value = (0, '{"isp": "Test"}')
        success, v4, v6 = cfdiag.step_dns("example.com")
        self.assertTrue(success)

    @patch('cfdiag.run_command')
    def test_ocsp_stapling(self, mock_run):
        mock_run.return_value = (0, "OCSP Response Status: successful")
        with patch('shutil.which', return_value='/usr/bin/openssl'):
            cfdiag.step_ocsp("example.com")

    @patch('cfdiag.run_command')
    def test_hsts_preload(self, mock_run):
        output_headers = """HTTP/2 200
strict-transport-security: max-age=31536000; includeSubDomains; preload
"""
        output_api = '{"status": "preloaded"}'
        mock_run.side_effect = [(0, output_headers), (0, output_api)]
        cfdiag.step_security_headers("example.com")

    @patch('cfdiag.run_command')
    def test_redirects(self, mock_run):
        mock_run.side_effect = [(0, "http://next.com"), (0, "")] 
        cfdiag.step_redirects("example.com")

    @patch('cfdiag.run_command')
    def test_waf_evasion(self, mock_run):
        mock_run.side_effect = [(0, "200"), (0, "403"), (0, "200")]
        cfdiag.step_waf_evasion("example.com")
        
    @patch('cfdiag.check_internet_connection')
    @patch('cfdiag.step_dns')
    @patch('cfdiag.step_http')
    @patch('cfdiag.step_tcp')
    @patch('cfdiag.run_command')
    @patch('cfdiag.step_redirects')
    @patch('cfdiag.step_waf_evasion')
    @patch('cfdiag.step_ocsp')
    def test_run_diagnostics_integration(self, mock_ocsp, mock_waf, mock_red, mock_run, mock_tcp, mock_http, mock_dns, mock_net):
        mock_net.return_value = True
        mock_dns.return_value = (True, ["1.1.1.1"], [])
        mock_http.return_value = ("SUCCESS", 200, False, {})
        mock_tcp.return_value = True
        mock_run.return_value = (0, "Mock Output")
        
        with patch('cfdiag.save_history', return_value={}), patch('cfdiag.save_metrics'):
            with patch('os.makedirs'), patch('cfdiag.FileLogger.save_to_file'):
                 with patch('cfdiag.FileLogger', return_value=self.mock_logger_instance):
                     cfdiag.run_diagnostics_wrapper("example.com", None, None, True, False, False, {})
             
        self.mock_logger_instance.save_html.assert_called()

    def test_curl_flags(self):
        # Test flag generation
        self.mock_get_context.return_value = {'ipv4': True, 'proxy': 'http://proxy'}
        flags = cfdiag.get_curl_flags()
        self.assertIn("-4", flags)
        self.assertIn("--proxy http://proxy", flags)

if __name__ == '__main__':
    unittest.main()