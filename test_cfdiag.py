#!/usr/bin/env python3
import unittest
from unittest.mock import patch, MagicMock
import cfdiag
import socket
import ssl
import sys
import io

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
        # Case 1: Success
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        self.assertTrue(cfdiag.check_internet_connection())
        
        # Case 2: Failure (Exception on both attempts)
        mock_conn.side_effect = socket.error("Network Unreachable")
        self.assertFalse(cfdiag.check_internet_connection())

    @patch('cfdiag.socket.getaddrinfo')
    @patch('cfdiag.run_command')
    def test_dns_resolution(self, mock_run, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(socket.AF_INET, 0, 0, '', ('192.0.2.1', 443))]
        mock_run.return_value = (0, '{"isp": "Test"}')
        success, v4, v6 = cfdiag.step_dns("example.com")
        self.assertTrue(success)
        self.assertIn('192.0.2.1', v4)

    @patch('cfdiag.run_command')
    def test_propagation(self, mock_run):
        mock_run.return_value = (0, "ns1.new.com.")
        with patch('shutil.which', return_value='/usr/bin/dig'):
            status = cfdiag.step_propagation("example.com", "ns1.new.com")
            self.assertEqual(status, "MATCH")

    @patch('cfdiag.run_command')
    def test_dnssec(self, mock_run):
        mock_run.side_effect = [(0, "12345 13 2 ..."), (0, "A 5 3 3600 ... RRSIG ...")]
        with patch('shutil.which', return_value='/usr/bin/dig'):
            status = cfdiag.step_dnssec("example.com")
            self.assertEqual(status, "SIGNED")

    @patch('cfdiag.socket.socket')
    def test_http3_udp(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        success = cfdiag.step_http3_udp("example.com")
        self.assertTrue(success)

    @patch('cfdiag.run_command')
    def test_http_status(self, mock_run):
        mock_run.return_value = (0, "HTTP/2 200 \n")
        status, code, waf = cfdiag.step_http("example.com")
        self.assertEqual(status, "SUCCESS")

    @patch('cfdiag.socket.create_connection')
    def test_tcp(self, mock_conn):
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        self.assertTrue(cfdiag.step_tcp("example.com"))

    @patch('cfdiag.step_dns')
    @patch('cfdiag.step_http')
    @patch('cfdiag.step_tcp')
    @patch('cfdiag.check_internet_connection') # Must mock this or it tries to connect
    def test_run_diagnostics_batch_wrapper(self, mock_net, mock_tcp, mock_http, mock_dns):
        mock_net.return_value = True
        mock_dns.return_value = (True, [], [])
        mock_http.return_value = ("SUCCESS", 200, False)
        mock_tcp.return_value = True
        
        with patch('os.makedirs'), patch('cfdiag.logger.save_to_file'):
            res = cfdiag.run_diagnostics("example.com")
            self.assertEqual(res['domain'], "example.com")
            self.assertEqual(res['dns'], "OK")

if __name__ == '__main__':
    unittest.main()
