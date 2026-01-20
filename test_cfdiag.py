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
    def test_ocsp_stapling(self, mock_run):
        mock_run.return_value = (0, "OCSP Response Status: successful")
        with patch('shutil.which', return_value='/usr/bin/openssl'):
            cfdiag.network.step_ocsp("example.com")

    @patch('cfdiag.network.ssl.create_default_context')
    def test_ssl_keylog(self, mock_ssl_context):
        self.mock_get_context.return_value = {'keylog_file': 'keys.log'}
        mock_ctx = MagicMock()
        mock_ssl_context.return_value = mock_ctx
        with patch('cfdiag.network.socket.create_connection'):
             cfdiag.network.step_ssl("example.com")
        self.assertEqual(mock_ctx.keylog_filename, 'keys.log')

    def test_grafana_output(self):
        capturedOutput = io.StringIO()
        sys.stdout = capturedOutput
        cfdiag.core.generate_grafana()
        sys.stdout = sys.__stdout__
        self.assertIn("cfdiag_http_ttfb_seconds", capturedOutput.getvalue())

    def test_curl_flags_header(self):
        self.mock_get_context.return_value = {'headers': ['X-Foo: Bar'], 'ipv4': True}
        flags = cfdiag.utils.get_curl_flags()
        self.assertIn("-4", flags)
        self.assertIn('-H "X-Foo: Bar"', flags)

    @patch('cfdiag.reporting.urllib.request.urlopen')
    def test_webhook(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        
        cfdiag.reporting.send_webhook("http://hook", "test.com", {"dns": "OK"})
        mock_urlopen.assert_called()

if __name__ == '__main__':
    unittest.main()