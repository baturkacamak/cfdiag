#!/usr/bin/env python3
import unittest
from unittest.mock import patch, MagicMock
import os
import sys

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import cfdiag.network
import cfdiag.core
from cfdiag.utils import CLOUDFLARE_IPS


class TestCloudflareIPRangeLogic(unittest.TestCase):
    def test_ip_range_cidr_logic(self):
        # TEST CASE 5: IP Range (CIDR) Logic Test
        cf_ip = "104.16.0.0"         # Should fall into a Cloudflare range
        local_ip = "192.168.1.1"     # Local / Private IP
        parked_ip = "185.53.177.20"  # Parked domain IP (not Cloudflare)

        self.assertTrue(
            cfdiag.network._ip_in_cidr_ranges(cf_ip, CLOUDFLARE_IPS),
            "104.16.0.0 should be inside a Cloudflare IP range",
        )
        self.assertFalse(
            cfdiag.network._ip_in_cidr_ranges(local_ip, CLOUDFLARE_IPS),
            "192.168.1.1 must not be inside any Cloudflare range",
        )
        self.assertFalse(
            cfdiag.network._ip_in_cidr_ranges(parked_ip, CLOUDFLARE_IPS),
            "185.53.177.20 must not be inside any Cloudflare range",
        )


class TestDetectCloudflareUsage(unittest.TestCase):
    @patch("cfdiag.network.run_command")
    def test_positive_cloudflare_ip_match(self, mock_run):
        """
        TEST CASE 1: Positive check
        If the IP is in a Cloudflare range, we should return True without relying on NS.
        """
        mock_run.return_value = (0, "")  # Should not be needed when IP already matches
        uses_cf = cfdiag.network.detect_cloudflare_usage(
            "www.cloudflare.com", ["104.16.0.0"], []
        )
        self.assertTrue(uses_cf)

    @patch("cfdiag.network.shutil.which", return_value=True)
    @patch("cfdiag.network.run_command")
    def test_negative_google_infra(self, mock_run, mock_which):
        """
        TEST CASE 2: Negative check (Google infrastructure)
        IP is not Cloudflare, NS records are ns*.google.com -> should return False.
        """
        mock_run.return_value = (
            0,
            "ns1.google.com.\nns2.google.com.\n",
        )
        uses_cf = cfdiag.network.detect_cloudflare_usage(
            "google.com", ["142.250.184.78"], []
        )
        self.assertFalse(uses_cf)

    @patch("cfdiag.network.shutil.which", return_value=True)
    @patch("cfdiag.network.run_command")
    def test_negative_parked_domain(self, mock_run, mock_which):
        """
        TEST CASE 3: Negative check (parked domain)
        Both IP and NS are non-Cloudflare -> should return False.
        """
        mock_run.return_value = (
            0,
            "parkdns1.okens.domains.\nparkdns2.okens.domains.\n",
        )
        uses_cf = cfdiag.network.detect_cloudflare_usage(
            "aussiecasinofinder.com", ["185.53.177.20"], []
        )
        self.assertFalse(uses_cf)

    @patch("cfdiag.network.shutil.which", return_value=True)
    @patch("cfdiag.network.run_command")
    def test_negative_regular_hosting(self, mock_run, mock_which):
        """
        TEST CASE 4: Negative check (regular hosting)
        example.com usually does not use Cloudflare; IP/NS are non-Cloudflare -> False.
        """
        mock_run.return_value = (
            0,
            "a.iana-servers.net.\nb.iana-servers.net.\n",
        )
        uses_cf = cfdiag.network.detect_cloudflare_usage(
            "example.com", ["93.184.216.34"], []
        )
        self.assertFalse(uses_cf)


class TestSummaryCloudflareMessages(unittest.TestCase):
    def setUp(self):
        # Shared fake logger
        self.logger = MagicMock()
        self.logger.log = MagicMock()

    @patch("cfdiag.core.detect_cloudflare_usage", return_value=True)
    @patch("cfdiag.core.get_logger")
    def test_summary_positive_cloudflare_message(self, mock_get_logger, mock_detect):
        """
        TEST CASE 1: Positive summary check
        When Cloudflare is in use, the summary MUST contain
          "[PASS] Cloudflare Edge Network is reachable"
        """
        mock_get_logger.return_value = self.logger

        dns_res = (True, ["104.16.0.0"], [])
        http_res = ("SUCCESS", 200, False, {})
        tcp_res = True
        cf_res = True
        mtu_res = True
        ssl_res = True
        cf_trace_res = (False, {})
        origin_res = None
        alt_ports_res = (False, [])
        dnssec_status = "DISABLED"
        prop_status = "N/A"
        history_diff = {}

        cfdiag.core.generate_summary(
            "www.cloudflare.com",
            dns_res,
            http_res,
            tcp_res,
            cf_res,
            mtu_res,
            ssl_res,
            cf_trace_res,
            origin_res,
            alt_ports_res,
            dnssec_status,
            prop_status,
            history_diff,
        )

        messages = [args[0] for args, _ in self.logger.log.call_args_list]
        joined = "\n".join(str(m) for m in messages)
        self.assertIn("Cloudflare Edge Network is reachable", joined)
        self.assertNotIn("Target is NOT using Cloudflare", joined)

    @patch("cfdiag.core.detect_cloudflare_usage", return_value=False)
    @patch("cfdiag.core.get_logger")
    def test_summary_negative_no_cloudflare_message(self, mock_get_logger, mock_detect):
        """
        TEST CASE 2–4: Negative summary checks
        When Cloudflare is NOT in use:
          - "Cloudflare Edge Network is reachable" MUST NOT appear.
          - Instead, "Target is NOT using Cloudflare" MUST be present.
        """
        mock_get_logger.return_value = self.logger

        dns_res = (True, ["93.184.216.34"], [])
        http_res = ("SUCCESS", 200, False, {})
        tcp_res = True
        cf_res = False
        mtu_res = True
        ssl_res = True
        cf_trace_res = (False, {})
        origin_res = None
        alt_ports_res = (False, [])
        dnssec_status = "DISABLED"
        prop_status = "N/A"
        history_diff = {}

        cfdiag.core.generate_summary(
            "example.com",
            dns_res,
            http_res,
            tcp_res,
            cf_res,
            mtu_res,
            ssl_res,
            cf_trace_res,
            origin_res,
            alt_ports_res,
            dnssec_status,
            prop_status,
            history_diff,
        )

        messages = [args[0] for args, _ in self.logger.log.call_args_list]
        joined = "\n".join(str(m) for m in messages)
        self.assertNotIn("Cloudflare Edge Network is reachable", joined)
        self.assertIn("Target is NOT using Cloudflare", joined)


if __name__ == "__main__":
    unittest.main()

