#!/usr/bin/env python3
import os
import ssl
import sys
import unittest
from unittest.mock import patch, MagicMock

import certifi

# Ensure project root is in path for direct test execution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import cfdiag.network


class TestCertifiBundleSanity(unittest.TestCase):
    def test_certifi_where_path_exists(self):
        """
        TEST CASE 5: File Path Existence Check (Sanity Check)
        Ensure certifi.where() returns an existing .pem file path.
        """
        path = certifi.where()
        self.assertIsInstance(path, str)
        self.assertTrue(os.path.exists(path))
        self.assertTrue(path.endswith(".pem"))


class TestSSLContextWithCertifi(unittest.TestCase):
    @patch("cfdiag.network.socket.create_connection")
    @patch("cfdiag.network.ssl.create_default_context")
    @patch("cfdiag.network.get_logger")
    def test_unit_context_uses_certifi_cafile(self, mock_get_logger, mock_create_default_context, mock_create_connection):
        """
        TEST CASE 3: Unit Test (Argument Verification via Mocking)
        Verify ssl.create_default_context is called with cafile=certifi.where().
        """
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        fake_context = MagicMock()
        mock_create_default_context.return_value = fake_context

        # Mock connection / handshake chain
        sock_cm = MagicMock()
        ssl_sock_cm = MagicMock()
        mock_create_connection.return_value.__enter__.return_value = sock_cm
        fake_context.wrap_socket.return_value.__enter__.return_value = ssl_sock_cm
        ssl_sock_cm.getpeercert.return_value = {"notAfter": "dummy"}

        cfdiag.network.step_ssl("www.example.com")

        # Assert ssl.create_default_context was called with cafile=certifi.where()
        expected_cafile = certifi.where()
        mock_create_default_context.assert_called_with(cafile=expected_cafile)


class TestRealWorldSSLWithCertifi(unittest.TestCase):
    @unittest.skipIf(os.environ.get("CFDIAG_SKIP_NETWORK_TESTS") == "1", "Network tests disabled")
    def test_real_world_positive_valid_certificate(self):
        """
        TEST CASE 1: Real-World Positive Test (Valid Certificate)
        Verify that a valid global site no longer causes CERTIFICATE_VERIFY_FAILED.
        """
        # Use a well-known site with a valid certificate.
        ok = cfdiag.network.step_ssl("www.google.com")
        self.assertTrue(ok)

    @unittest.skipIf(os.environ.get("CFDIAG_SKIP_NETWORK_TESTS") == "1", "Network tests disabled")
    def test_real_world_negative_invalid_certificate(self):
        """
        TEST CASE 2: Real-World Negative Test (Invalid Certificate)
        Ensure invalid/expired/self-signed certificates still fail.
        """
        # badssl.com provides controlled invalid cert scenarios for testing.
        ok_expired = cfdiag.network.step_ssl("expired.badssl.com")
        ok_self_signed = cfdiag.network.step_ssl("self-signed.badssl.com")
        self.assertFalse(ok_expired)
        self.assertFalse(ok_self_signed)


class TestRequestsIntegration(unittest.TestCase):
    @unittest.skip("Project does not use requests; no HTTP client integration to verify.")
    def test_requests_verify_not_disabled(self):
        """
        TEST CASE 4: HTTP Client Integration (Requests Library)
        Skipped because this project uses curl via subprocess, not the requests library.
        """
        pass


if __name__ == "__main__":
    unittest.main()

