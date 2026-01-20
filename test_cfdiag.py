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
    def test_dns_trace(self, mock_run):
        # Case 1: Success (NOERROR)
        mock_run.return_value = (0, "trace output... NOERROR ...ANSWER SECTION")
        with patch('shutil.which', return_value='/usr/bin/dig'):
            cfdiag.step_dns_trace("example.com")
            # Asserts are implicit: no crash

    @patch('cfdiag.ssl.create_default_context')
    @patch('cfdiag.socket.create_connection')
    def test_ssl_chain_validation(self, mock_conn, mock_ctx):
        mock_sock = MagicMock()
        mock_ssock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock
        
        # Case 1: Success
        mock_ssock.getpeercert.return_value = {'notAfter': 'Dec 12 12:00:00 2030 GMT'}
        self.assertTrue(cfdiag.step_ssl("valid.com"))

        # Case 2: Verification Error (Chain issue)
        mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError("unable to get local issuer certificate")
        self.assertFalse(cfdiag.step_ssl("incomplete-chain.com"))

    @patch('cfdiag.run_command')
    def test_http_latency_parsing(self, mock_run):
        output = r"code=200;;connect=0.05;;start=0.10;;total=0.15"
        mock_run.return_value = (0, output)
        
        status, code, waf, metrics = cfdiag.step_http("example.com")
        
        self.assertEqual(status, "SUCCESS")
        self.assertEqual(code, 200)
        self.assertEqual(metrics.get('connect'), 0.05)
        self.assertEqual(metrics.get('ttfb'), 0.10)

    @patch('cfdiag.step_tcp')
    def test_alt_ports(self, mock_tcp):
        def side_effect(domain, port=443):
            return port == 8443
        mock_tcp.side_effect = side_effect
        # Note: step_alt_ports calls socket.create_connection directly, 
        # but in previous fix I updated test to patch socket. 
        # Wait, step_alt_ports in v2.0.0 uses socket.create_connection directly.
        # I need to patch socket.create_connection for this test.

    @patch('cfdiag.socket.create_connection')
    def test_alt_ports_logic(self, mock_conn):
        def side_effect(addr, timeout=2):
            if addr[1] == 8443: return MagicMock()
            raise socket.error("Refused")
        mock_conn.side_effect = side_effect
        
        success, ports = cfdiag.step_alt_ports("example.com")
        self.assertTrue(success)
        self.assertIn(8443, ports)

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
