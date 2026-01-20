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
        self.assertIn('--max-time 10', flags)

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
            self.assertIn("| DNS | ✅ PASS |", args)

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

class TestNetwork(unittest.TestCase):
    def setUp(self):
        cfdiag.utils.set_context({})
        self.log_patcher = patch('cfdiag.network.get_logger')
        self.mock_get_logger = self.log_patcher.start()
        self.mock_logger = MagicMock()
        self.mock_get_logger.return_value = self.mock_logger

    def tearDown(self):
        self.log_patcher.stop()

    @patch('cfdiag.network.socket.getaddrinfo')
    def test_step_dns_ipv4(self, mock_gai):
        mock_gai.return_value = [(socket.AF_INET, 0, 0, '', ('1.1.1.1', 443))]
        with patch('cfdiag.network.run_command', return_value=(0, "")):
            ok, v4, v6 = cfdiag.network.step_dns("example.com")
        self.assertTrue(ok)
        self.assertEqual(v4, ['1.1.1.1'])
        self.assertEqual(v6, [])

    @patch('cfdiag.network.socket.getaddrinfo')
    def test_step_dns_ipv6(self, mock_gai):
        mock_gai.return_value = [(socket.AF_INET6, 0, 0, '', ('::1', 443))]
        with patch('cfdiag.network.run_command', return_value=(0, "")):
            ok, v4, v6 = cfdiag.network.step_dns("example.com")
        self.assertTrue(ok)
        self.assertEqual(v6, ['::1'])

    @patch('cfdiag.network.run_command')
    def test_step_http_success(self, mock_run):
        output = """HTTP/2 200
server: cloudflare
cf-cache-status: HIT
code=200;;connect=0.1;;start=0.2;;total=0.3"""
        mock_run.return_value = (0, output)
        res, code, waf, metrics = cfdiag.network.step_http("example.com")
        self.assertEqual(res, "SUCCESS")
        self.assertEqual(code, 200)
        self.assertEqual(metrics['total'], 0.3)

    @patch('cfdiag.network.run_command')
    def test_step_redirects_loop(self, mock_run):
        mock_run.return_value = (0, "http://loop.com")
        cfdiag.network.step_redirects("example.com")
        self.mock_logger.add_html_step.assert_called()

    @patch('cfdiag.network.run_command')
    def test_step_waf_evasion(self, mock_run):
        mock_run.side_effect = [(0, "200"), (0, "403"), (0, "200")]
        cfdiag.network.step_waf_evasion("example.com")
        self.mock_logger.add_html_step.assert_called()

    @patch('cfdiag.network.run_command')
    def test_step_speed(self, mock_run):
        mock_run.return_value = (0, "500000") # 500KB/s
        cfdiag.network.step_speed("example.com")
        self.mock_logger.add_html_step.assert_called()

    @patch('cfdiag.network.run_command')
    @patch('shutil.which', return_value=True)
    def test_step_dns_benchmark(self, mock_which, mock_run):
        mock_run.return_value = (0, "1.2.3.4")
        cfdiag.network.step_dns_benchmark("example.com")
        self.mock_logger.add_html_step.assert_called()

    @patch('cfdiag.network.socket.create_connection')
    def test_step_ssl_keylog(self, mock_conn):
        cfdiag.utils.set_context({'keylog_file': 'test.log'})
        with patch('ssl.create_default_context') as mock_ctx_ctor:
            mock_ctx = MagicMock()
            mock_ctx_ctor.return_value = mock_ctx
            cfdiag.network.step_ssl("example.com")
            self.assertEqual(mock_ctx.keylog_filename, 'test.log')

class TestEdgeCases(unittest.TestCase):
    def setUp(self):
        cfdiag.utils.set_context({})
        self.log_patcher = patch('cfdiag.network.get_logger')
        self.mock_get_logger = self.log_patcher.start()
        self.mock_logger = MagicMock()
        self.mock_get_logger.return_value = self.mock_logger

    def tearDown(self):
        self.log_patcher.stop()

    @patch('cfdiag.network.socket.getaddrinfo')
    def test_dns_nxdomain(self, mock_gai):
        mock_gai.side_effect = socket.gaierror("Name or service not known")
        ok, v4, v6 = cfdiag.network.step_dns("nxdomain.com")
        self.assertFalse(ok)
        self.assertEqual(v4, [])

    @patch('cfdiag.network.run_command')
    def test_http_522_timeout(self, mock_run):
        output = "code=522;;connect=10;;start=10;;total=10"
        mock_run.return_value = (0, output)
        res, code, waf, metrics = cfdiag.network.step_http("timeout.com")
        self.assertEqual(code, 522)
        self.assertEqual(res, "FAIL")

    @patch('cfdiag.network.run_command')
    def test_http_403_waf(self, mock_run):
        output = "code=403;;connect=0.1;;start=0.1;;total=0.1"
        mock_run.return_value = (0, output)
        res, code, waf, metrics = cfdiag.network.step_http("waf.com")
        self.assertEqual(code, 403)
        self.assertEqual(res, "FAIL")

    @patch('cfdiag.network.socket.create_connection')
    def test_tcp_timeout(self, mock_conn):
        mock_conn.side_effect = socket.timeout("timed out")
        ok = cfdiag.network.step_tcp("timeout.com")
        self.assertFalse(ok)
        self.mock_logger.add_html_step.assert_called()
        args = self.mock_logger.add_html_step.call_args[0]
        self.assertEqual(args[1], "FAIL")

    @patch('cfdiag.network.socket.create_connection')
    def test_ssl_handshake_fail(self, mock_conn):
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        
        with patch('ssl.create_default_context') as mock_ctx_ctor:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.side_effect = ssl.SSLError("Handshake failed")
            mock_ctx_ctor.return_value = mock_ctx
            
            ok = cfdiag.network.step_ssl("badssl.com")
            self.assertFalse(ok)

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
            patch('cfdiag.core.generate_summary')
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

    def test_main_speed_and_benchmark(self):
        with patch('sys.argv', ['cfdiag', 'example.com', '--speed', '--benchmark-dns']):
            with patch('cfdiag.core.step_speed') as mock_speed, \
                 patch('cfdiag.core.step_dns_benchmark') as mock_bench:
                cfdiag.core.main()
                mock_speed.assert_called()
                mock_bench.assert_called()

if __name__ == '__main__':
    unittest.main()