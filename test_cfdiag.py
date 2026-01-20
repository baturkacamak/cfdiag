#!/usr/bin/env python3
import unittest
from unittest.mock import patch, MagicMock, mock_open
import cfdiag
import socket
import ssl
import sys
import io
import json

class TestCFDiag(unittest.TestCase):

    def setUp(self):
        self.log_patcher = patch('cfdiag.logger', MagicMock())
        self.mock_logger = self.log_patcher.start()
        self.mock_logger.silent = True
        self.mock_logger.verbose = False

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
    def test_http_latency_parsing(self, mock_run):
        output = r"code=200\nconnect=0.05\nstart=0.10\ntotal=0.15"
        mock_run.return_value = (0, output)
        
        status, code, waf, metrics = cfdiag.step_http("example.com")
        
        self.assertEqual(status, "SUCCESS")
        self.assertEqual(code, 200)
        self.assertEqual(metrics.get('connect'), 0.05)
        self.assertEqual(metrics.get('ttfb'), 0.10)

    @patch('cfdiag.run_command')
    def test_config_loading(self, mock_run):
        config_data = json.dumps({
            "default": {"origin": "1.1.1.1"},
            "profiles": {
                "prod": {"domain": "prod.com", "origin": "2.2.2.2"}
            }
        })
        
        with patch('builtins.open', mock_open(read_data=config_data)):
            with patch('os.path.exists', return_value=True):
                # Test Default
                conf = cfdiag.load_config()
                self.assertEqual(conf.get('profiles', {}).get('prod', {}).get('domain'), "prod.com")
                
                # Test Profile
                prof = cfdiag.load_config("prod")
                self.assertEqual(prof.get('origin'), "2.2.2.2")

    @patch('cfdiag.socket.create_connection')
    def test_tcp(self, mock_conn):
        mock_conn.return_value.__enter__.return_value = MagicMock()
        self.assertTrue(cfdiag.step_tcp("example.com"))

    @patch('cfdiag.step_dns')
    @patch('cfdiag.step_http')
    @patch('cfdiag.step_tcp')
    @patch('cfdiag.check_internet_connection')
    def test_run_diagnostics_batch_wrapper(self, mock_net, mock_tcp, mock_http, mock_dns):
        mock_net.return_value = True
        mock_dns.return_value = (True, [], [])
        mock_http.return_value = ("SUCCESS", 200, False, {})
        mock_tcp.return_value = True
        
        with patch('os.makedirs'), patch('cfdiag.logger.save_to_file'):
            res = cfdiag.run_diagnostics("example.com")
            self.assertEqual(res['domain'], "example.com")

if __name__ == '__main__':
    unittest.main()