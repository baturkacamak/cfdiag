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

class TestUtils(unittest.TestCase):
    def setUp(self):
        cfdiag.utils.set_context({})

    def test_get_curl_flags_empty(self):
        self.assertEqual(cfdiag.utils.get_curl_flags(), "")

    def test_get_curl_flags_ipv4(self):
        cfdiag.utils.set_context({'ipv4': True})
        self.assertIn("-4", cfdiag.utils.get_curl_flags())

    def test_get_curl_flags_ipv6(self):
        cfdiag.utils.set_context({'ipv6': True})
        self.assertIn("-6", cfdiag.utils.get_curl_flags())

    def test_get_curl_flags_proxy(self):
        cfdiag.utils.set_context({'proxy': 'http://proxy'})
        self.assertIn("--proxy http://proxy", cfdiag.utils.get_curl_flags())

    def test_get_curl_flags_headers(self):
        cfdiag.utils.set_context({'headers': ['H: V']})
        flags = cfdiag.utils.get_curl_flags()
        self.assertIn('-H "H: V"', flags)

    def test_get_curl_flags_timeout(self):
        cfdiag.utils.set_context({'timeout': 5})
        flags = cfdiag.utils.get_curl_flags()
        self.assertIn('--connect-timeout 5', flags)

class TestReporting(unittest.TestCase):
    def setUp(self):
        self.logger = cfdiag.reporting.FileLogger(verbose=True)
        self.logger.html_data = {"domain": "example.com", "timestamp": "now", "steps": [], "summary": []}

    def test_log_console(self):
        captured = io.StringIO()
        with patch('sys.stdout', captured):
            self.logger.log_console("test")
        self.assertIn("test", captured.getvalue())

    def test_save_to_file(self):
        self.logger.log_file("test log")
        with patch('builtins.open', mock_open()) as m:
            self.logger.save_to_file("out.txt")
            m().write.assert_called_with("test log\n")

    def test_save_html(self):
        self.logger.html_data['steps'].append({"title": "DNS", "status": "PASS", "details": "ok"})
        with patch('builtins.open', mock_open()) as m:
            self.logger.save_html("out.html")
            handle = m()
            args = handle.write.call_args[0][0]
            self.assertIn("DNS", args)
            self.assertIn("PASS", args)

    def test_save_markdown(self):
        self.logger.html_data['summary'].append("DNS: PASS")
        with patch('builtins.open', mock_open()) as m:
            self.logger.save_markdown("out.md")
            args = m().write.call_args[0][0]
            self.assertIn("| DNS | [PASS] PASS |", args)

    def test_save_junit(self):
        self.logger.html_data['steps'].append({"title": "DNS", "status": "FAIL", "details": "timeout"})
        with patch('builtins.open', mock_open()) as m:
            self.logger.save_junit("out.xml")
            args = m().write.call_args[0][0]
            self.assertIn('<failure message="FAIL">timeout</failure>', args)

    @patch('cfdiag.reporting.urllib.request.urlopen')
    def test_webhook(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        cfdiag.reporting.send_webhook("http://hook", "dom", {})
        mock_urlopen.assert_called()

class TestSystem(unittest.TestCase):
    def test_lint_config_pass(self):
        content = "set_real_ip_from 173.245.48.0/20;"
        with patch('builtins.open', mock_open(read_data=content)):
            with patch('os.path.exists', return_value=True):
                with patch('cfdiag.system.print_success'):
                    cfdiag.system.step_lint_config("nginx.conf")

    def test_audit_pass(self):
        results = {'ssl_ok': True, 'http_status': 200}
        with patch('sys.stdout', io.StringIO()) as captured:
            cfdiag.system.step_audit("example.com", results)
            self.assertIn("PASSED", captured.getvalue())

class TestServer(unittest.TestCase):
    def test_run_server(self):
        with patch('cfdiag.server.socketserver.TCPServer') as mock_server:
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

class TestNetwork(unittest.TestCase):
    def setUp(self):
        cfdiag.utils.set_context({})
        self.log_patcher = patch('cfdiag.network.get_logger')
        self.mock_get_logger = self.log_patcher.start()
        self.mock_logger = MagicMock()
        self.mock_get_logger.return_value = self.mock_logger

    def tearDown(self):
        self.log_patcher.stop()

    @patch('cfdiag.network.analyze_dns')
    @patch('cfdiag.network.probe_dns')
    def test_step_dns_ipv4(self, mock_probe, mock_analyze):
        mock_probe.return_value = {
            "domain": "example.com", 
            "records": {"A": ["1.1.1.1"], "AAAA": [], "CNAME": [], "NS": []}, 
            "resolvers_used": [], 
            "dnssec_valid": None,
            "error": None, 
            "raw_output": ""
        }
        mock_analyze.return_value = {
            "status": cfdiag.types.Severity.PASS,
            "classification": "DNS_PASS",
            "human_reason": "Resolved",
            "meta": {},
            "recommendations": []
        }
        ok, v4, v6 = cfdiag.network.step_dns("example.com")
        self.assertTrue(ok)
        self.assertEqual(v4, ['1.1.1.1'])

    @patch('cfdiag.network.analyze_http')
    @patch('cfdiag.network.probe_http')
    def test_step_http_success(self, mock_probe, mock_analyze):
        mock_probe.return_value = {
            "url": "https://example.com",
            "status_code": 200,
            "headers": {},
            "redirect_chain": [],
            "timings": {"connect": 0.1, "ttfb": 0.2, "total": 0.3, "namelookup": 0.05},
            "body_sample": "",
            "is_waf_challenge": False,
            "http_version": "1.1",
            "error": None
        }
        mock_analyze.return_value = {
            "status": cfdiag.types.Severity.PASS,
            "classification": "HTTP_PASS",
            "human_reason": "OK",
            "meta": {},
            "recommendations": []
        }
        res, code, waf, metrics = cfdiag.network.step_http("example.com")
        self.assertEqual(res, "SUCCESS")
        self.assertEqual(code, 200)

    @patch('cfdiag.network.run_command')
    def test_step_graph(self, mock_run):
        mock_run.return_value = (0, "1  1.1.1.1 (1.1.1.1)")
        with patch('sys.stdout', io.StringIO()) as captured:
            cfdiag.network.step_graph("example.com")
            self.assertIn("digraph G", captured.getvalue())

    @patch('cfdiag.network.run_command')
    def test_step_doh(self, mock_run):
        mock_response = json.dumps({"Status": 0, "Answer": [{"type": 1, "data": "1.2.3.4"}]})
        mock_run.return_value = (0, mock_response)
        cfdiag.network.step_doh("example.com")
        self.mock_logger.add_html_step.assert_called()

    @patch('cfdiag.network.run_command')
    def test_step_speed(self, mock_run):
        mock_run.return_value = (0, "1048576")
        cfdiag.network.step_speed("example.com")
        self.mock_logger.add_html_step.assert_called()

    @patch('cfdiag.network.run_command')
    @patch('shutil.which', return_value=True)
    def test_step_dns_benchmark(self, mock_which, mock_run):
        mock_run.return_value = (0, "1.2.3.4")
        cfdiag.network.step_dns_benchmark("example.com")
        self.mock_logger.add_html_step.assert_called()

    @patch('cfdiag.network.analyze_tls')
    @patch('cfdiag.network.probe_tls')
    def test_step_ssl_keylog(self, mock_probe, mock_analyze):
        cfdiag.utils.set_context({'keylog_file': 'test.log'})
        mock_probe.return_value = {
            "handshake_success": True,
            "cert_valid": True,
            "protocol_version": "TLSv1.3",
            "cert_expiry": "2025-01-01",
            "cert_start": "2024-01-01",
            "cert_issuer": "Let's Encrypt",
            "verification_errors": [],
            "ocsp_stapled": False,
            "error": None,
            "cipher": "AES",
            "cert_subject": "example.com"
        }
        mock_analyze.return_value = {
            "status": cfdiag.types.Severity.PASS,
            "classification": "SSL_PASS",
            "human_reason": "Secure",
            "meta": {},
            "recommendations": []
        }
        
        cfdiag.network.step_ssl("example.com")
        mock_probe.assert_called_with("example.com", timeout=5, keylog_file="test.log")

    @patch('cfdiag.network.analyze_mtu')
    @patch('cfdiag.network.probe_mtu')
    def test_step_mtu(self, mock_probe, mock_analyze):
        mock_probe.return_value = {
            "path_mtu": 1500,
            "fragmentation_point": 0,
            "packets_sent": 5,
            "packets_lost": 0,
            "error": None
        }
        mock_analyze.return_value = {
            "status": cfdiag.types.Severity.PASS,
            "classification": "MTU_PASS",
            "human_reason": "Standard MTU",
            "meta": {"mtu": 1500, "lost": 0},
            "recommendations": []
        }
        cfdiag.network.step_mtu("example.com")
        self.mock_logger.add_html_step.assert_called()
        args = self.mock_logger.add_html_step.call_args[0]
        # In step_mtu we print/log the MTU
        self.assertIn("1500", args[2])

    @patch('cfdiag.network.socket.create_connection')
    @patch('cfdiag.network.ssl.create_default_context')
    def test_step_websocket(self, mock_ssl, mock_conn):
        mock_sock = MagicMock()
        mock_ssock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        mock_ssl.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ssock.recv.return_value = b"HTTP/1.1 101 Switching Protocols\r\n\r\n"
        cfdiag.network.step_websocket("example.com")
        self.mock_logger.add_html_step.assert_called()
        args = self.mock_logger.add_html_step.call_args[0]
        self.assertEqual(args[1], "PASS")

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
            patch('cfdiag.core.analyze_logs'),
            patch('cfdiag.network.step_mtu', return_value=True),
            patch('cfdiag.core.step_websocket') # Patch core import
        ]
        for p in self.patchers: p.start()

    def tearDown(self):
        for p in self.patchers: p.stop()

    def test_main_basic(self):
        with patch('sys.argv', ['cfdiag', 'example.com']):
            cfdiag.core.main()

    def test_main_ipv4_ipv6_conflict(self):
        with patch('sys.argv', ['cfdiag', 'example.com', '--ipv4', '--ipv6']):
            with self.assertRaises(SystemExit):
                with patch('sys.stderr', io.StringIO()):
                    cfdiag.core.main()

    def test_main_json_output(self):
        with patch('sys.argv', ['cfdiag', 'example.com', '--json']):
            with patch('sys.stdout', io.StringIO()) as captured:
                cfdiag.core.main()
                self.assertIn('"http_metrics":', captured.getvalue())

    def test_main_grafana(self):
        with patch('sys.argv', ['cfdiag', '--grafana']):
            with patch('sys.stdout', io.StringIO()) as captured:
                cfdiag.core.main()
                self.assertIn('"title": "CFDiag Dashboard"', captured.getvalue())

    def test_main_completion(self):
        with patch('sys.argv', ['cfdiag', '--completion', 'bash']):
            with patch('sys.stdout', io.StringIO()) as captured:
                cfdiag.core.main()
                self.assertIn('complete -F _cfdiag', captured.getvalue())

    def test_main_diff(self):
        with patch('sys.argv', ['cfdiag', '--diff', 'a.txt', 'b.txt']):
            with patch('builtins.open', mock_open(read_data="DNS: PASS")):
                cfdiag.core.main()

    def test_main_ws(self):
        with patch('sys.argv', ['cfdiag', 'example.com', '--ws']):
            with patch('cfdiag.core.step_websocket') as mock_ws:
                cfdiag.core.main()
                mock_ws.assert_called_with('example.com')

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