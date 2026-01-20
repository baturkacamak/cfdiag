#!/usr/bin/env python3
import unittest
from unittest.mock import patch, MagicMock, call
import cfdiag
import socket
import ssl

class TestCFDiag(unittest.TestCase):

    def setUp(self):
        # Suppress logging
        self.log_patcher = patch('cfdiag.logger')
        self.mock_logger = self.log_patcher.start()

    def tearDown(self):
        self.log_patcher.stop()

    @patch('cfdiag.socket.gethostbyname_ex')
    @patch('cfdiag.run_command')
    def test_dns_resolution(self, mock_run, mock_socket):
        # Case 1: Success
        mock_socket.return_value = ('example.com', [], ['192.0.2.1'])
        # Mock curl ASN output
        mock_run.return_value = (0, '{"isp": "TestISP"}')
        
        success, ips = cfdiag.step_dns("example.com")
        self.assertTrue(success)
        self.assertEqual(ips, ['192.0.2.1'])

        # Case 2: Failure
        mock_socket.side_effect = socket.gaierror("Name or service not known")
        success, ips = cfdiag.step_dns("fail.com")
        self.assertFalse(success)

    @patch('cfdiag.socket.create_connection')
    def test_tcp_connectivity(self, mock_create_connection):
        # Case 1: Success
        # create_connection returns a socket object (context manager)
        mock_sock = MagicMock()
        mock_create_connection.return_value.__enter__.return_value = mock_sock
        
        self.assertTrue(cfdiag.step_tcp("example.com"))

        # Case 2: Failure
        mock_create_connection.side_effect = socket.error("Connection refused")
        self.assertFalse(cfdiag.step_tcp("example.com"))

    @patch('cfdiag.ssl.create_default_context')
    @patch('cfdiag.socket.create_connection')
    def test_ssl_check(self, mock_create_connection, mock_ssl_context):
        # Mocking the SSL context -> wrap_socket -> getpeercert chain
        mock_context = MagicMock()
        mock_ssock = MagicMock()
        mock_sock = MagicMock()
        
        mock_ssl_context.return_value = mock_context
        mock_create_connection.return_value.__enter__.return_value = mock_sock
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock
        
        # Case 1: Success
        mock_ssock.getpeercert.return_value = {'notAfter': 'Mar 16 12:00:00 2026 GMT'}
        self.assertTrue(cfdiag.step_ssl("example.com"))

        # Case 2: No cert data
        mock_ssock.getpeercert.return_value = {}
        self.assertFalse(cfdiag.step_ssl("example.com"))
        
        # Case 3: Connection Fail
        mock_create_connection.side_effect = socket.error("Fail")
        self.assertFalse(cfdiag.step_ssl("example.com"))

    @patch('cfdiag.run_command')
    def test_http_status_parsing(self, mock_run):
        # Case 1: 200 OK
        mock_run.return_value = (0, "HTTP/2 200 \ndate: ...")
        status, code, waf = cfdiag.step_http("example.com")
        self.assertEqual(status, "SUCCESS")
        
        # Case 2: 503 WAF
        # First call (HEAD) returns 503
        # Second call (Body) returns "Just a moment..."
        mock_run.side_effect = [
            (0, "HTTP/2 503 Service Unavailable\n"),
            (0, "<html><title>Just a moment...</title></html>")
        ]
        status, code, waf = cfdiag.step_http("example.com")
        self.assertEqual(status, "WAF_BLOCK")
        self.assertTrue(waf)

    @patch('cfdiag.step_tcp')
    def test_alt_ports(self, mock_tcp):
        # Mock step_tcp to return True only for port 8443
        def side_effect(domain, port=443):
            return port == 8443
        
        mock_tcp.side_effect = side_effect
        
        success, ports = cfdiag.step_alt_ports("example.com")
        self.assertTrue(success)
        self.assertEqual(ports, [8443])

    @patch('cfdiag.run_command')
    def test_mtu_check(self, mock_run):
        # Case 1: Success
        mock_run.return_value = (0, "0% loss")
        self.assertTrue(cfdiag.step_mtu("example.com"))
        
        # Case 2: Fail large, pass small
        mock_run.side_effect = [(1, "Request timed out"), (0, "0% loss")]
        self.assertFalse(cfdiag.step_mtu("example.com")) # returns False but prints info

if __name__ == '__main__':
    unittest.main()
