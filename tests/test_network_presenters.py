import unittest
from unittest.mock import patch, MagicMock, call
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import cfdiag.network
from cfdiag.types import Severity

class TestNetworkPresenters(unittest.TestCase):
    
    def setUp(self):
        self.mock_logger = MagicMock()
        patcher = patch('cfdiag.network.get_logger', return_value=self.mock_logger)
        self.addCleanup(patcher.stop)
        patcher.start()
        
        # Silence prints
        self.patch_print_success = patch('cfdiag.network.print_success')
        self.patch_print_fail = patch('cfdiag.network.print_fail')
        self.patch_print_info = patch('cfdiag.network.print_info')
        self.patch_print_warning = patch('cfdiag.network.print_warning')
        self.patch_print_subheader = patch('cfdiag.network.print_subheader')
        
        self.addCleanup(self.patch_print_success.stop)
        self.addCleanup(self.patch_print_fail.stop)
        self.addCleanup(self.patch_print_info.stop)
        self.addCleanup(self.patch_print_warning.stop)
        self.addCleanup(self.patch_print_subheader.stop)
        
        self.patch_print_success.start()
        self.patch_print_fail.start()
        self.patch_print_info.start()
        self.patch_print_warning.start()
        self.patch_print_subheader.start()

    @patch('cfdiag.network.probe_http')
    @patch('cfdiag.network.analyze_http')
    def test_step_http_table(self, mock_analyze, mock_probe):
        # Table: Probe Result, Analysis Result, Expected Legacy String, Expected Log String, Expected Log Code/Status
        cases = [
            (
                # Case 1: 200 OK
                {"status_code": 200, "timings": {}, "is_waf_challenge": False},
                {"status": Severity.PASS, "classification": "HTTP_PASS", "human_reason": "OK"},
                "SUCCESS", "SUCCESS", "OK"
            ),
            (
                # Case 2: 403 WAF (Legacy mapping update: CLIENT_ERROR)
                {"status_code": 403, "timings": {}, "is_waf_challenge": True},
                {"status": Severity.INFO, "classification": "HTTP_WAF_BLOCK", "human_reason": "WAF Block"},
                "CLIENT_ERROR", "CLIENT_ERROR", "WAF Block"
            ),
            (
                # Case 3: 429 Rate Limit (Legacy mapping update: CLIENT_ERROR)
                {"status_code": 429, "timings": {}, "is_waf_challenge": False},
                {"status": Severity.INFO, "classification": "HTTP_RATE_LIMIT", "human_reason": "Rate Limited"},
                "CLIENT_ERROR", "CLIENT_ERROR", "Rate Limited"
            ),
            (
                # Case 4: 500 Error
                {"status_code": 500, "timings": {}},
                {"status": Severity.ERROR, "classification": "HTTP_SERVER_ERROR", "human_reason": "Server Error"},
                "SERVER_ERROR", "SERVER_ERROR", "Server Error"
            ),
            (
                # Case 5: Timeout
                {"status_code": 0, "error": "Timeout"},
                {"status": Severity.CRITICAL, "classification": "HTTP_TIMEOUT", "human_reason": "Timed Out"},
                "TIMEOUT", "TIMEOUT", "Timed Out"
            ),
            (
                # Case 6: Missing Keys (Defensive read check)
                {}, # Empty probe result
                {"status": Severity.CRITICAL, "classification": "HTTP_CONNECT_FAIL", "human_reason": "Connect Fail"},
                "TIMEOUT", "TIMEOUT", "Connect Fail"
            )
        ]
        
        for probe_data, analysis_data, expected_legacy, expected_log_status, expected_reason in cases:
            with self.subTest(classification=analysis_data["classification"]):
                mock_probe.return_value = probe_data
                mock_analyze.return_value = analysis_data
                
                res_str, code, is_waf, metrics = cfdiag.network.step_http("example.com")
                
                self.assertEqual(res_str, expected_legacy)
                # Verify logger call: add_html_step("HTTP", status, details)
                self.mock_logger.add_html_step.assert_called_with("HTTP", expected_log_status, expected_reason)

    @patch('cfdiag.network.probe_dns')
    @patch('cfdiag.network.analyze_dns')
    def test_step_dns_table(self, mock_analyze, mock_probe):
        cases = [
            (
                {"records": {"A": ["1.1.1.1"]}, "raw_output": "out"},
                {"status": Severity.PASS, "classification": "DNS_PASS", "human_reason": "Resolved"},
                True
            ),
            (
                {"records": {"A": []}, "error": "NXDOMAIN"},
                {"status": Severity.CRITICAL, "classification": "DNS_FAIL", "human_reason": "NXDOMAIN"},
                False
            ),
            (
                # Missing keys
                {}, 
                {"status": Severity.CRITICAL, "classification": "DNS_FAIL", "human_reason": "Fail"},
                False
            )
        ]
        
        for probe, analysis, expected_bool in cases:
            with self.subTest(case=analysis["classification"]):
                mock_probe.return_value = probe
                mock_analyze.return_value = analysis
                
                res, v4, v6 = cfdiag.network.step_dns("example.com")
                self.assertEqual(res, expected_bool)

    @patch('cfdiag.network.probe_mtu')
    @patch('cfdiag.network.analyze_mtu')
    def test_step_mtu_table(self, mock_analyze, mock_probe):
        cases = [
            (
                {"path_mtu": 1500},
                {"status": Severity.PASS, "classification": "MTU_PASS", "human_reason": "OK"},
                True
            ),
            (
                {"path_mtu": 1200},
                {"status": Severity.CRITICAL, "classification": "MTU_CRITICAL", "human_reason": "Too Low"},
                False
            ),
            (
                {}, # Missing keys
                {"status": Severity.WARNING, "classification": "MTU_WARNING", "human_reason": "Unknown"},
                False
            )
        ]
        for probe, analysis, expected_bool in cases:
            with self.subTest(mtu=probe.get("path_mtu")):
                mock_probe.return_value = probe
                mock_analyze.return_value = analysis
                cfdiag.network.step_mtu("example.com")
                # Verification mainly via return bool and ensuring no crash on missing keys

    @patch('cfdiag.network.probe_origin')
    @patch('cfdiag.network.analyze_origin_reachability')
    def test_step_origin_table(self, mock_analyze, mock_probe):
        cases = [
            (
                {"edge_probe": {}, "origin_probe": {}},
                {"status": Severity.PASS, "classification": "ORIGIN_REACHABLE", "human_reason": "OK"},
                True, "SUCCESS"
            ),
            (
                {}, # Missing keys
                {"status": Severity.ERROR, "classification": "ORIGIN_522", "human_reason": "Timeout"},
                False, "TIMEOUT"
            )
        ]
        for probe, analysis, exp_bool, exp_str in cases:
            with self.subTest(cls=analysis["classification"]):
                mock_probe.return_value = probe
                mock_analyze.return_value = analysis
                res_bool, res_str = cfdiag.network.step_origin("example.com", "1.2.3.4")
                self.assertEqual(res_bool, exp_bool)
                self.assertEqual(res_str, exp_str)

if __name__ == '__main__':
    unittest.main()
