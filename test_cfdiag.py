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
        self.mock_logger_instance.html_data = {"domain": "test", "timestamp": "now", "steps": [], "summary": ["DNS: PASS"]}
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
    def test_speed_test(self, mock_run):
        # Mock curl outputting bytes/sec
        mock_run.return_value = (0, "1048576") # 1 MB/s
        cfdiag.network.step_speed("example.com")
        # Implicit assertion: no crash

    @patch('cfdiag.network.run_command')
    def test_dns_benchmark(self, mock_run):
        # Mock dig output
        mock_run.return_value = (0, "1.2.3.4")
        with patch('shutil.which', return_value='/usr/bin/dig'):
            cfdiag.network.step_dns_benchmark("example.com")

    def test_grafana_output(self):
        capturedOutput = io.StringIO()
        sys.stdout = capturedOutput
        cfdiag.core.generate_grafana()
        sys.stdout = sys.__stdout__
        self.assertIn("cfdiag_http_ttfb_seconds", capturedOutput.getvalue())

if __name__ == '__main__':
    unittest.main()
