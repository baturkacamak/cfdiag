#!/usr/bin/env python3
import unittest
from unittest.mock import patch, MagicMock, mock_open
import cfdiag
import socket
import json
import os

class TestCFDiag(unittest.TestCase):

    def setUp(self):
        # Patch get_logger to return a mock logger
        self.log_patcher = patch('cfdiag.get_logger')
        self.mock_get_logger = self.log_patcher.start()
        
        self.mock_logger_instance = MagicMock()
        self.mock_logger_instance.html_data = {"domain": "test", "timestamp": "now", "steps": [], "summary": []}
        self.mock_logger_instance.save_html = MagicMock()
        
        self.mock_get_logger.return_value = self.mock_logger_instance

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
    def test_run_diagnostics_integration(self, mock_waf, mock_red, mock_run, mock_tcp, mock_http, mock_dns, mock_net):
        mock_net.return_value = True
        mock_dns.return_value = (True, ["1.1.1.1"], [])
        mock_http.return_value = ("SUCCESS", 200, False, {})
        mock_tcp.return_value = True
        mock_run.return_value = (0, "Mock Output")
        
        with patch('cfdiag.save_history', return_value={}), patch('cfdiag.save_metrics'):
            with patch('os.makedirs'), patch('cfdiag.FileLogger.save_to_file'):
                 # We need to manually set the logger for the wrapper logic or call IMPL
                 # run_diagnostics sets the thread local logger using FileLogger()
                 # We need to patch FileLogger class to return our mock
                 with patch('cfdiag.FileLogger', return_value=self.mock_logger_instance):
                     cfdiag.run_diagnostics_wrapper("example.com", None, None, True, False, False)
             
        self.mock_logger_instance.save_html.assert_called()

if __name__ == '__main__':
    unittest.main()