#!/usr/bin/env python3
import unittest
from unittest.mock import patch, MagicMock
import cfdiag
import io
import sys

class TestCFDiag(unittest.TestCase):

    def setUp(self):
        # Suppress logging during tests to keep output clean
        self.log_patcher = patch('cfdiag.logger')
        self.mock_logger = self.log_patcher.start()

    def tearDown(self):
        self.log_patcher.stop()

    @patch('cfdiag.run_command')
    def test_dns_resolution(self, mock_run):
        # Case 1: Success
        mock_run.return_value = (0, "192.0.2.1\n")
        success, ips = cfdiag.step_dns("example.com")
        self.assertTrue(success)
        self.assertEqual(ips, ["192.0.2.1"])

        # Case 2: Failure (Empty output)
        mock_run.return_value = (0, "")
        success, ips = cfdiag.step_dns("example.com")
        self.assertFalse(success)

        # Case 3: Command Failure
        mock_run.return_value = (1, "")
        success, ips = cfdiag.step_dns("example.com")
        self.assertFalse(success)

    @patch('cfdiag.run_command')
    def test_http_status_parsing(self, mock_run):
        # Case 1: 200 OK
        mock_run.return_value = (0, "HTTP/2 200 \ndate: ...")
        status, code = cfdiag.step_http("example.com")
        self.assertEqual(status, "SUCCESS")
        self.assertEqual(code, 200)

        # Case 2: 404 Not Found (Client Error)
        mock_run.return_value = (0, "HTTP/1.1 404 Not Found\n...")
        status, code = cfdiag.step_http("example.com")
        self.assertEqual(status, "CLIENT_ERROR")
        self.assertEqual(code, 404)

        # Case 3: 500 Server Error
        mock_run.return_value = (0, "HTTP/1.1 500 Internal Error\n...")
        status, code = cfdiag.step_http("example.com")
        self.assertEqual(status, "SERVER_ERROR")
        self.assertEqual(code, 500)

        # Case 4: 522 Cloudflare Error (The one we fixed)
        mock_run.return_value = (0, "HTTP/2 522 \n...")
        status, code = cfdiag.step_http("example.com")
        self.assertEqual(status, "SERVER_ERROR")
        self.assertEqual(code, 522)

        # Case 5: 525 SSL Handshake Failed
        mock_run.return_value = (0, "HTTP/2 525 \n...")
        status, code = cfdiag.step_http("example.com")
        self.assertEqual(status, "SERVER_ERROR")
        self.assertEqual(code, 525)

        # Case 6: Connection Timeout (Curl code 28)
        mock_run.return_value = (28, "")
        status, code = cfdiag.step_http("example.com")
        self.assertEqual(status, "TIMEOUT")
        self.assertEqual(code, 0)
        
        # Case 7: Weird/Garbage output
        mock_run.return_value = (0, "Not an HTTP header\n")
        status, code = cfdiag.step_http("example.com")
        self.assertEqual(status, "WEIRD")

    @patch('cfdiag.run_command')
    def test_tcp_connectivity(self, mock_run):
        # Case 1: Success
        mock_run.return_value = (0, "Connection to ... succeeded!")
        self.assertTrue(cfdiag.step_tcp("example.com"))

        # Case 2: Failure
        mock_run.return_value = (1, "")
        self.assertFalse(cfdiag.step_tcp("example.com"))

    @patch('cfdiag.run_command')
    def test_ssl_check(self, mock_run):
        # Case 1: Success
        mock_run.return_value = (0, "notAfter=Mar 16 18:32:44 2026 GMT\n")
        self.assertTrue(cfdiag.step_ssl("example.com"))

        # Case 2: Failure
        mock_run.return_value = (1, "connect: errno=111")
        self.assertFalse(cfdiag.step_ssl("example.com"))

    @patch('cfdiag.run_command')
    def test_mtu_check(self, mock_run):
        # Case 1: Success (Standard MTU)
        mock_run.return_value = (0, "1480 bytes from ...")
        self.assertTrue(cfdiag.step_mtu("example.com"))

        # Case 2: Failure (Large packet fails, small passes)
        # The function calls run_command twice in this case.
        # We simulate this using side_effect with an iterator.
        mock_run.side_effect = [(1, "Packet filtered"), (0, "1260 bytes from ...")]
        self.assertFalse(cfdiag.step_mtu("example.com"))
        
        # Reset side_effect for next tests
        mock_run.side_effect = None

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
        self.assertEqual(details['ip'], '1.2.3.4')

        # Case 2: Failure (Not a CF site)
        mock_run.return_value = (0, "<html>Not found</html>")
        success, details = cfdiag.step_cf_trace("example.com")
        self.assertFalse(success)

    @patch('cfdiag.run_command')
    def test_origin_connect(self, mock_run):
        # Case 1: Success (Origin is UP)
        mock_run.return_value = (0, "HTTP/1.1 200 OK\n")
        connected, reason = cfdiag.step_origin_connect("example.com", "1.2.3.4")
        self.assertTrue(connected)
        self.assertEqual(reason, "SUCCESS")

        # Case 2: Failure (Origin is DOWN/Timeout)
        mock_run.return_value = (28, "")
        connected, reason = cfdiag.step_origin_connect("example.com", "1.2.3.4")
        self.assertFalse(connected)
        self.assertEqual(reason, "TIMEOUT")
        
        # Case 3: Error (Origin returns 500)
        mock_run.return_value = (0, "HTTP/1.1 500 Internal Error\n")
        connected, reason = cfdiag.step_origin_connect("example.com", "1.2.3.4")
        self.assertTrue(connected) # Connected successfully to the machine
        self.assertEqual(reason, "ERROR") # But it returned an error

if __name__ == '__main__':
    unittest.main()
