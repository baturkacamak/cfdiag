#!/usr/bin/env python3
import unittest
from unittest.mock import patch, MagicMock
import cfdiag
import io
import sys
import json

class TestCFDiag(unittest.TestCase):

    def setUp(self):
        # Suppress logging during tests to keep output clean
        self.log_patcher = patch('cfdiag.logger')
        self.mock_logger = self.log_patcher.start()

    def tearDown(self):
        self.log_patcher.stop()

    @patch('cfdiag.run_command')
    def test_dns_resolution(self, mock_run):
        # Case 1: Success with ASN
        mock_run.side_effect = [
            (0, "192.0.2.1\n"), # Dig result
            (0, '{"isp": "TestISP", "org": "TestOrg", "country": "TestLand"}') # Curl ASN result
        ]
        success, ips = cfdiag.step_dns("example.com")
        self.assertTrue(success)
        self.assertEqual(ips, ["192.0.2.1"])

        mock_run.side_effect = None # Reset

        # Case 2: Failure (Empty output)
        mock_run.return_value = (0, "")
        success, ips = cfdiag.step_dns("example.com")
        self.assertFalse(success)

    @patch('cfdiag.run_command')
    def test_http_status_parsing(self, mock_run):
        # Case 1: 200 OK
        mock_run.return_value = (0, "HTTP/2 200 \ndate: ...")
        status, code, waf = cfdiag.step_http("example.com")
        self.assertEqual(status, "SUCCESS")
        self.assertEqual(code, 200)
        self.assertFalse(waf)

        # Case 2: 404 Not Found (Client Error)
        mock_run.return_value = (0, "HTTP/1.1 404 Not Found\n...")
        status, code, waf = cfdiag.step_http("example.com")
        self.assertEqual(status, "CLIENT_ERROR")
        self.assertEqual(code, 404)

        # Case 3: 503 WAF Challenge
        # side_effect: first call (HEAD) returns 503, second call (BODY) returns Challenge text
        mock_run.side_effect = [
            (0, "HTTP/2 503 Service Unavailable\n"),
            (0, "<html><title>Just a moment...</title>...cf-captcha-container...</html>")
        ]
        status, code, waf = cfdiag.step_http("example.com")
        self.assertEqual(status, "WAF_BLOCK")
        self.assertEqual(code, 503)
        self.assertTrue(waf)
        
        mock_run.side_effect = None

        # Case 4: 522 Cloudflare Error
        mock_run.return_value = (0, "HTTP/2 522 \n...")
        status, code, waf = cfdiag.step_http("example.com")
        self.assertEqual(status, "SERVER_ERROR")
        self.assertEqual(code, 522)

    @patch('cfdiag.run_command')
    def test_tcp_connectivity(self, mock_run):
        # Case 1: Success
        mock_run.return_value = (0, "Connection to ... succeeded!")
        self.assertTrue(cfdiag.step_tcp("example.com"))

        # Case 2: Failure
        mock_run.return_value = (1, "")
        self.assertFalse(cfdiag.step_tcp("example.com"))

    @patch('cfdiag.run_command')
    def test_alt_ports(self, mock_run):
        # Case: 8443 open, others closed
        # The loop runs for CF_PORTS. We need side_effect to return success for one specific call.
        # CF_PORTS = [8443, 2053, 2083, 2087, 2096]
        
        def side_effect(cmd, **kwargs):
            if "8443" in cmd:
                return (0, "Success")
            return (1, "Refused")
            
        mock_run.side_effect = side_effect
        
        success, ports = cfdiag.step_alt_ports("example.com")
        self.assertTrue(success)
        self.assertIn(8443, ports)
        self.assertNotIn(2053, ports)

    @patch('cfdiag.run_command')
    def test_ssl_check(self, mock_run):
        # Case 1: Success
        mock_run.return_value = (0, "notAfter=Mar 16 18:32:44 2026 GMT\n")
        self.assertTrue(cfdiag.step_ssl("example.com"))

    @patch('cfdiag.run_command')
    def test_cf_trace(self, mock_run):
        # Case 1: Success
        output = """fl=123
h=example.com
ip=1.2.3.4
colo=MAD
warp=off
"""
        mock_run.return_value = (0, output)
        success, details = cfdiag.step_cf_trace("example.com")
        self.assertTrue(success)
        self.assertEqual(details['colo'], 'MAD')

    @patch('cfdiag.run_command')
    def test_origin_connect(self, mock_run):
        # Case 1: Success
        mock_run.return_value = (0, "HTTP/1.1 200 OK\n")
        connected, reason = cfdiag.step_origin_connect("example.com", "1.2.3.4")
        self.assertTrue(connected)
        self.assertEqual(reason, "SUCCESS")

if __name__ == '__main__':
    unittest.main()