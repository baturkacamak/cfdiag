#!/usr/bin/env python3
import unittest
from unittest.mock import patch, MagicMock, mock_open, call
import sys
import io
import os
import json
import socket
import ssl

# Ensure root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import cfdiag.core
import cfdiag.network
import cfdiag.reporting
import cfdiag.utils
import cfdiag.system
import cfdiag.server
import cfdiag.log_analysis

class TestServer(unittest.TestCase):
    def test_run_server(self):
        # We can't actually run the server loop, but we can verify it calls socketserver
        with patch('cfdiag.server.socketserver.TCPServer') as mock_server:
            # raise KeyboardInterrupt to exit the loop immediately
            mock_server.return_value.__enter__.return_value.serve_forever.side_effect = KeyboardInterrupt
            cfdiag.server.run_diagnostic_server(8080)
            mock_server.assert_called()

class TestLogAnalysis(unittest.TestCase):
    def test_analyze_logs(self):
        log_content = '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 522 2326'
        with patch('builtins.open', mock_open(read_data=log_content)):
            with patch('os.path.exists', return_value=True):
                with patch('sys.stdout', io.StringIO()) as captured:
                    cfdiag.log_analysis.analyze_logs("access.log")
                    self.assertIn("HTTP 522", captured.getvalue())

class TestCoreCLI(unittest.TestCase):
    def setUp(self):
        self.patchers = [
            patch('cfdiag.core.step_dns', return_value=(True, [], [])),
            patch('cfdiag.core.step_http', return_value=("SUCCESS", 200, False, {})),
            patch('cfdiag.core.step_tcp', return_value=True),
            patch('cfdiag.core.check_internet_connection', return_value=True),
            patch('cfdiag.core.check_dependencies'),
            patch('cfdiag.core.save_history', return_value={}),
            patch('cfdiag.reporting.FileLogger'),
            patch('cfdiag.core.generate_summary'),
            patch('cfdiag.core.step_doh'),
            patch('cfdiag.core.step_audit'),
            patch('cfdiag.core.step_lint_config'),
            patch('cfdiag.core.run_mtr'),
            patch('cfdiag.network.step_graph'),
            patch('cfdiag.network.step_speed'),
            patch('cfdiag.network.step_dns_benchmark'),
            patch('cfdiag.network.step_redirects'),
            patch('cfdiag.network.step_waf_evasion'),
            patch('cfdiag.core.run_diagnostic_server'),
            patch('cfdiag.core.analyze_logs')
        ]
        for p in self.patchers: p.start()

    def tearDown(self):
        for p in self.patchers: p.stop()

    def test_main_serve(self):
        with patch('sys.argv', ['cfdiag', '--serve', '9090']):
            with patch('cfdiag.core.run_diagnostic_server') as mock_serve:
                cfdiag.core.main()
                mock_serve.assert_called_with(9090)

    def test_main_analyze(self):
        with patch('sys.argv', ['cfdiag', '--analyze-logs', 'log.txt']):
            with patch('cfdiag.core.analyze_logs') as mock_analyze:
                cfdiag.core.main()
                mock_analyze.assert_called_with('log.txt')

if __name__ == '__main__':
    unittest.main()