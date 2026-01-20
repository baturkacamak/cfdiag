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

    @patch('cfdiag.socket.getaddrinfo')
    @patch('cfdiag.run_command')
    def test_dns_resolution(self, mock_run, mock_getaddrinfo):
        # Case 1: Success with IPv4 and IPv6
        # getaddrinfo returns list of (family, type, proto, canonname, sockaddr)
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1', 443)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2001:db8::1', 443, 0, 0))
        ]
        # Mock curl ASN output
        mock_run.return_value = (0, '{"isp": "TestISP"}')
        
        success, ipv4, ipv6 = cfdiag.step_dns("example.com")
        self.assertTrue(success)
        self.assertIn('192.0.2.1', ipv4)
        self.assertIn('2001:db8::1', ipv6)

        # Case 2: Failure
        mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")
        success, ipv4, ipv6 = cfdiag.step_dns("fail.com")
        self.assertFalse(success)

    @patch('cfdiag.run_command')
    def test_domain_status(self, mock_run):
        # Case 1: Active
        output = '{"status": ["client transfer prohibited", "active"], "events": [{"eventAction": "expiration", "eventDate": "2030-01-01"}]}'
        mock_run.return_value = (0, output)
        cfdiag.step_domain_status("example.com")
        # We assume it prints success if no exception raised.
        
        # Case 2: JSON Error
        mock_run.return_value = (0, "Not JSON")
        cfdiag.step_domain_status("example.com")
        # Should catch JSONDecodeError and warn

    @patch('cfdiag.socket.create_connection')
    def test_tcp_connectivity(self, mock_create_connection):
        # Case 1: Success
        mock_sock = MagicMock()
        mock_create_connection.return_value.__enter__.return_value = mock_sock
        self.assertTrue(cfdiag.step_tcp("example.com"))

        # Case 2: Failure
        mock_create_connection.side_effect = socket.error("Connection refused")
        self.assertFalse(cfdiag.step_tcp("example.com"))

    @patch('cfdiag.ssl.create_default_context')
    @patch('cfdiag.socket.create_connection')
    def test_ssl_check(self, mock_create_connection, mock_ssl_context):
        mock_context = MagicMock()
        mock_ssock = MagicMock()
        mock_sock = MagicMock()
        
        mock_ssl_context.return_value = mock_context
        mock_create_connection.return_value.__enter__.return_value = mock_sock
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock
        
        # Case 1: Success
        mock_ssock.getpeercert.return_value = {'notAfter': 'Mar 16 12:00:00 2026 GMT'}
        self.assertTrue(cfdiag.step_ssl("example.com"))

    @patch('cfdiag.run_command')
    def test_http_status_parsing(self, mock_run):
        # Case 1: 200 OK
        mock_run.return_value = (0, "HTTP/2 200 \ndate: ...")
        status, code, waf = cfdiag.step_http("example.com")
        self.assertEqual(status, "SUCCESS")
        
        # Case 2: 503 WAF
        mock_run.side_effect = [
            (0, "HTTP/2 503 Service Unavailable\n"),
            (0, "<html><title>Just a moment...</title></html>")
        ]
        status, code, waf = cfdiag.step_http("example.com")
        self.assertEqual(status, "WAF_BLOCK")
        self.assertTrue(waf)

    @patch('cfdiag.step_tcp')
    def test_alt_ports(self, mock_tcp):
        def side_effect(domain, port=443):
            return port == 8443
        mock_tcp.side_effect = side_effect
        
        success, ports = cfdiag.step_alt_ports("example.com")
        self.assertTrue(success)
        self.assertIn(8443, ports)

if __name__ == '__main__':
    unittest.main()