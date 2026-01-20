#!/usr/bin/env python3
import unittest
from unittest.mock import patch, MagicMock, mock_open
import cfdiag
import socket
import json
import os

class TestCFDiag(unittest.TestCase):

    def setUp(self):
        self.log_patcher = patch('cfdiag.logger', MagicMock())
        self.mock_logger = self.log_patcher.start()
        self.mock_logger.html_data = {"domain": "test", "timestamp": "now", "steps": [], "summary": []}
        self.mock_logger.save_html = MagicMock()

    def tearDown(self):
        self.log_patcher.stop()

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

    @patch('cfdiag.socket.gethostbyname')
    def test_blacklist_check(self, mock_gethostbyname):
        mock_gethostbyname.return_value = "127.0.0.2"
        cfdiag.step_blacklist("example.com", "1.2.3.4")

    @patch('cfdiag.run_command')
    def test_cache_headers(self, mock_run):
        output = """HTTP/2 200
server: cloudflare
cf-cache-status: HIT
"""
        cfdiag.step_cache_headers(output)

    @patch('cfdiag.run_command')
    def test_security_headers(self, mock_run):
        output = """HTTP/2 200
strict-transport-security: max-age=31536000
"""
        mock_run.return_value = (0, output)
        cfdiag.step_security_headers("example.com")

    @patch('cfdiag.check_internet_connection')
    @patch('cfdiag.step_dns')
    @patch('cfdiag.step_http')
    @patch('cfdiag.step_tcp')
    @patch('cfdiag.run_command')
    @patch('cfdiag.step_security_headers') 
    @patch('cfdiag.save_history')
    @patch('cfdiag.save_metrics')
    def test_run_diagnostics_integration(self, mock_metrics, mock_hist, mock_sec, mock_run, mock_tcp, mock_http, mock_dns, mock_net):
        mock_net.return_value = True
        mock_dns.return_value = (True, ["1.1.1.1"], [])
        mock_http.return_value = ("SUCCESS", 200, False, {})
        mock_tcp.return_value = True
        mock_run.return_value = (0, "Mock Output")
        mock_hist.return_value = {"ttfb": 0.1} # Previous history
        
        self.mock_logger.save_html.return_value = True
        
        with patch('os.makedirs'), patch('cfdiag.logger.save_to_file'):
             cfdiag.run_diagnostics("example.com", export_metrics=True)
             
        mock_metrics.assert_called()
        mock_hist.assert_called()

if __name__ == '__main__':
    unittest.main()
