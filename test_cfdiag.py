#!/usr/bin/env python3
import unittest
from unittest.mock import patch, MagicMock
import cfdiag
import socket
import ssl
import sys
import io
import platform

class TestCFDiag(unittest.TestCase):

    def setUp(self):
        self.log_patcher = patch('cfdiag.logger', MagicMock())
        self.mock_logger = self.log_patcher.start()
        self.mock_logger.silent = True
        self.mock_logger.verbose = False

    def tearDown(self):
        self.log_patcher.stop()

    # --- Connectivity & Core ---

    @patch('cfdiag.socket.create_connection')
    def test_internet_check(self, mock_conn):
        mock_conn.return_value.__enter__.return_value = MagicMock()
        self.assertTrue(cfdiag.check_internet_connection())
        
        mock_conn.side_effect = socket.error("Fail")
        self.assertFalse(cfdiag.check_internet_connection())

    # --- DNS ---

    @patch('cfdiag.socket.getaddrinfo')
    @patch('cfdiag.run_command')
    def test_dns_resolution(self, mock_run, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, 0, 0, '', ('1.1.1.1', 443)),
            (socket.AF_INET6, 0, 0, '', ('::1', 443))
        ]
        mock_run.return_value = (0, '{"isp": "Test"}')
        
        success, v4, v6 = cfdiag.step_dns("example.com")
        self.assertTrue(success)
        self.assertIn('1.1.1.1', v4)
        self.assertIn('::1', v6)

    @patch('cfdiag.run_command')
    def test_dnssec(self, mock_run):
        # Disabled
        mock_run.return_value = (0, "")
        with patch('shutil.which', return_value='dig'):
            self.assertEqual(cfdiag.step_dnssec("example.com"), "DISABLED")
        
        # Signed
        mock_run.side_effect = [(0, "DS record"), (0, "RRSIG")]
        with patch('shutil.which', return_value='dig'):
            self.assertEqual(cfdiag.step_dnssec("example.com"), "SIGNED")

    # --- HTTP & WAF ---

    @patch('cfdiag.run_command')
    def test_http_waf(self, mock_run):
        # 403 with WAF body
        mock_run.side_effect = [
            (0, "HTTP/2 403 Forbidden\n"), # Head
            (0, "<html><div class='cf-captcha-container'></div></html>") # Body
        ]
        status, code, waf = cfdiag.step_http("waf.com")
        self.assertEqual(status, "WAF_BLOCK")
        self.assertTrue(waf)

    # --- SSL ---

    @patch('cfdiag.ssl.create_default_context')
    @patch('cfdiag.socket.create_connection')
    def test_ssl_valid(self, mock_conn, mock_ctx):
        mock_sock = MagicMock()
        mock_ssock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock
        
        mock_ssock.getpeercert.return_value = {'notAfter': 'Dec 12 12:00:00 2030 GMT'}
        
        self.assertTrue(cfdiag.step_ssl("valid.com"))

    @patch('cfdiag.ssl.create_default_context')
    @patch('cfdiag.socket.create_connection')
    def test_ssl_handshake_fail(self, mock_conn, mock_ctx):
        mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLError("Handshake fail")
        self.assertFalse(cfdiag.step_ssl("bad-ssl.com"))

    # --- MTU (OS Specifics) ---

    @patch('cfdiag.run_command')
    @patch('platform.system')
    def test_mtu_windows(self, mock_sys, mock_run):
        mock_sys.return_value = "Windows"
        mock_run.return_value = (0, "Reply from...")
        
        cfdiag.step_mtu("win.com")
        # Check if correct flags used
        args, _ = mock_run.call_args
        self.assertIn("-f -l", args[0])

    @patch('cfdiag.run_command')
    @patch('platform.system')
    def test_mtu_linux(self, mock_sys, mock_run):
        mock_sys.return_value = "Linux"
        mock_run.return_value = (0, "bytes from")
        
        cfdiag.step_mtu("linux.com")
        args, _ = mock_run.call_args
        self.assertIn("-M do -s", args[0])

    # --- Alt Ports ---

    @patch('cfdiag.socket.create_connection')
    def test_alt_ports(self, mock_conn):
        # Simulate 8443 open, others closed
        def side_effect(address, timeout=2):
            if address[1] == 8443:
                return MagicMock()
            raise socket.error("Refused")
        
        mock_conn.side_effect = side_effect
        
        success, open_ports = cfdiag.step_alt_ports("example.com")
        self.assertTrue(success)
        self.assertEqual(open_ports, [8443])

    @patch('cfdiag.socket.create_connection')
    def test_alt_ports_all_closed(self, mock_conn):
        mock_conn.side_effect = socket.error("Refused")
        success, open_ports = cfdiag.step_alt_ports("example.com")
        self.assertFalse(success)
        self.assertEqual(open_ports, [])

    # --- Origin & CF Trace ---

    @patch('cfdiag.run_command')
    def test_cf_trace(self, mock_run):
        mock_run.return_value = (0, "fl=123\ncolo=LHR\nip=1.2.3.4")
        success, details = cfdiag.step_cf_trace("example.com")
        self.assertTrue(success)
        self.assertEqual(details['colo'], 'LHR')

    @patch('cfdiag.run_command')
    def test_origin_connect(self, mock_run):
        mock_run.return_value = (0, "HTTP/1.1 521 Origin Down\n")
        success, reason = cfdiag.step_origin("example.com", "1.2.3.4")
        self.assertTrue(success) # Connected
        self.assertEqual(reason, "ERROR") # But returned error status

if __name__ == '__main__':
    unittest.main()