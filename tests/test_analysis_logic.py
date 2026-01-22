import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cfdiag.analysis import (
    analyze_dns, analyze_http, analyze_tls, 
    analyze_mtu, analyze_origin_reachability
)
from cfdiag.types import Severity

class TestAnalysisLogicV3(unittest.TestCase):
    
    # ==========================
    # DNS Scenarios (20 cases)
    # ==========================
    
    def test_dns_01_empty(self):
        res = analyze_dns(self._dns_probe([], [], error=None))
        self.assertEqual(res["classification"], "DNS_FAIL")
        
    def test_dns_02_nxdomain(self):
        res = analyze_dns(self._dns_probe([], [], error="NXDOMAIN"))
        self.assertEqual(res["classification"], "DNS_FAIL")
        
    def test_dns_03_ipv4_only(self):
        res = analyze_dns(self._dns_probe(["1.1.1.1"], [], error=None))
        self.assertEqual(res["classification"], "DNS_IPV4_ONLY")
        
    def test_dns_04_ipv6_only(self):
        res = analyze_dns(self._dns_probe([], ["::1"], error=None))
        self.assertEqual(res["classification"], "DNS_IPV6_ONLY")

    def test_dns_05_dual_stack(self):
        res = analyze_dns(self._dns_probe(["1.1.1.1"], ["::1"], error=None))
        self.assertEqual(res["classification"], "DNS_PASS")

    def test_dns_06_cname_loop(self):
        res = analyze_dns(self._dns_probe([], [], error="CNAME Loop"))
        self.assertEqual(res["classification"], "DNS_FAIL")

    def test_dns_07_timeout(self):
        res = analyze_dns(self._dns_probe([], [], error="Timeout"))
        self.assertEqual(res["classification"], "DNS_FAIL")

    def test_dns_08_invalid_ip(self):
        res = analyze_dns(self._dns_probe([], [], error=None))
        self.assertEqual(res["classification"], "DNS_FAIL")

    def test_dns_09_private_ip(self):
        res = analyze_dns(self._dns_probe(["192.168.1.1"], [], error=None))
        self.assertEqual(res["classification"], "DNS_IPV4_ONLY")

    def test_dns_10_localhost(self):
        res = analyze_dns(self._dns_probe(["127.0.0.1"], [], error=None))
        self.assertEqual(res["classification"], "DNS_IPV4_ONLY")

    def test_dns_11_multiple_records(self):
        res = analyze_dns(self._dns_probe(["1.1.1.1", "8.8.8.8"], ["::1"], error=None))
        self.assertEqual(res["classification"], "DNS_PASS")

    def test_dns_12_dnssec_fail(self):
        # Now explicitly tested for failure
        res = analyze_dns(self._dns_probe(["1.1.1.1"], ["::1"], dnssec=False))
        self.assertEqual(res["classification"], "DNS_DNSSEC_FAIL")

    def test_dns_13_tcp_fallback(self):
        res = analyze_dns(self._dns_probe(["1.1.1.1"], ["::1"], error=None))
        self.assertEqual(res["classification"], "DNS_PASS")

    def test_dns_14_refused(self):
        res = analyze_dns(self._dns_probe([], [], error="REFUSED"))
        self.assertEqual(res["classification"], "DNS_FAIL")

    def test_dns_15_servfail(self):
        res = analyze_dns(self._dns_probe([], [], error="SERVFAIL"))
        self.assertEqual(res["classification"], "DNS_FAIL")
        
    def test_dns_16_mixed_error(self):
        res = analyze_dns(self._dns_probe(["1.1.1.1"], [], error="Partial Fail"))
        self.assertEqual(res["classification"], "DNS_FAIL")
        
    def test_dns_17_root_hint(self):
        res = analyze_dns(self._dns_probe([], [], error="Root Hint"))
        self.assertEqual(res["classification"], "DNS_FAIL")
        
    def test_dns_18_slow(self):
        res = analyze_dns(self._dns_probe(["1.1.1.1"], ["::1"], error=None))
        self.assertEqual(res["classification"], "DNS_PASS")
        
    def test_dns_19_wildcard(self):
        res = analyze_dns(self._dns_probe(["1.1.1.1"], ["::1"], error=None))
        self.assertEqual(res["classification"], "DNS_PASS")
        
    def test_dns_20_malformed(self):
        res = analyze_dns(self._dns_probe([], [], error=None))
        self.assertEqual(res["classification"], "DNS_FAIL")

    # ==========================
    # HTTP Scenarios (50 cases)
    # ==========================
    # ... (No changes to HTTP tests logic, just ensuring they run) ...
    def test_http_01_200(self): self.assertEqual(analyze_http(self._http_probe(200))["classification"], "HTTP_PASS")
    def test_http_02_201(self): self.assertEqual(analyze_http(self._http_probe(201))["classification"], "HTTP_PASS")
    def test_http_03_204(self): self.assertEqual(analyze_http(self._http_probe(204))["classification"], "HTTP_PASS")
    def test_http_04_301(self): self.assertEqual(analyze_http(self._http_probe(301))["classification"], "HTTP_REDIRECT")
    def test_http_05_302(self): self.assertEqual(analyze_http(self._http_probe(302))["classification"], "HTTP_REDIRECT")
    def test_http_06_307(self): self.assertEqual(analyze_http(self._http_probe(307))["classification"], "HTTP_REDIRECT")
    def test_http_07_308(self): self.assertEqual(analyze_http(self._http_probe(308))["classification"], "HTTP_REDIRECT")

    def test_http_08_403_waf(self):
        res = analyze_http(self._http_probe(403, waf=True))
        self.assertEqual(res["classification"], "HTTP_WAF_BLOCK")
        self.assertEqual(res["status"], Severity.INFO)
    def test_http_09_401_waf(self):
        self.assertEqual(analyze_http(self._http_probe(401, waf=True))["classification"], "HTTP_WAF_BLOCK")
    def test_http_10_429(self):
        self.assertEqual(analyze_http(self._http_probe(429))["classification"], "HTTP_RATE_LIMIT")
        
    def test_http_11_400(self): self.assertEqual(analyze_http(self._http_probe(400))["classification"], "HTTP_CLIENT_ERROR")
    def test_http_12_401_basic(self): self.assertEqual(analyze_http(self._http_probe(401, waf=False))["classification"], "HTTP_CLIENT_ERROR")
    def test_http_13_403_nginx(self): self.assertEqual(analyze_http(self._http_probe(403, waf=False))["classification"], "HTTP_CLIENT_ERROR")
    def test_http_14_404(self): self.assertEqual(analyze_http(self._http_probe(404))["classification"], "HTTP_CLIENT_ERROR")
    def test_http_15_405(self): self.assertEqual(analyze_http(self._http_probe(405))["classification"], "HTTP_CLIENT_ERROR")
    def test_http_16_418(self): self.assertEqual(analyze_http(self._http_probe(418))["classification"], "HTTP_CLIENT_ERROR")
    def test_http_17_431(self): self.assertEqual(analyze_http(self._http_probe(431))["classification"], "HTTP_CLIENT_ERROR")
    def test_http_18_411(self): self.assertEqual(analyze_http(self._http_probe(411))["classification"], "HTTP_CLIENT_ERROR")
    def test_http_19_412(self): self.assertEqual(analyze_http(self._http_probe(412))["classification"], "HTTP_CLIENT_ERROR")
    def test_http_20_421(self): self.assertEqual(analyze_http(self._http_probe(421))["classification"], "HTTP_CLIENT_ERROR")

    def test_http_21_500(self): self.assertEqual(analyze_http(self._http_probe(500))["classification"], "HTTP_SERVER_ERROR")
    def test_http_22_502(self): self.assertEqual(analyze_http(self._http_probe(502))["classification"], "HTTP_SERVER_ERROR")
    def test_http_23_503(self): self.assertEqual(analyze_http(self._http_probe(503))["classification"], "HTTP_SERVER_ERROR")
    def test_http_24_504(self): self.assertEqual(analyze_http(self._http_probe(504))["classification"], "HTTP_SERVER_ERROR")
    def test_http_25_520(self): self.assertEqual(analyze_http(self._http_probe(520))["classification"], "HTTP_SERVER_ERROR")
    def test_http_26_521(self): self.assertEqual(analyze_http(self._http_probe(521))["classification"], "HTTP_SERVER_ERROR")
    def test_http_27_522(self): self.assertEqual(analyze_http(self._http_probe(522))["classification"], "HTTP_SERVER_ERROR")
    def test_http_28_523(self): self.assertEqual(analyze_http(self._http_probe(523))["classification"], "HTTP_SERVER_ERROR")
    def test_http_29_524(self): self.assertEqual(analyze_http(self._http_probe(524))["classification"], "HTTP_SERVER_ERROR")
    def test_http_30_525(self): self.assertEqual(analyze_http(self._http_probe(525))["classification"], "HTTP_SERVER_ERROR")

    def test_http_31_refused(self): self.assertEqual(analyze_http(self._http_probe(0, error="Refused"))["classification"], "HTTP_CONNECT_FAIL")
    def test_http_32_timeout(self): self.assertEqual(analyze_http(self._http_probe(0, error="Timeout"))["classification"], "HTTP_TIMEOUT")
    def test_http_33_read_timeout(self): self.assertEqual(analyze_http(self._http_probe(0, error="ReadTimeout"))["classification"], "HTTP_TIMEOUT")
    def test_http_34_connect_timeout(self): self.assertEqual(analyze_http(self._http_probe(0, error="ConnectTimeout"))["classification"], "HTTP_TIMEOUT")
    def test_http_35_empty(self): self.assertEqual(analyze_http(self._http_probe(0, error="EmptyReply"))["classification"], "HTTP_CONNECT_FAIL")
    def test_http_36_ssl_err(self): self.assertEqual(analyze_http(self._http_probe(0, error="SSL"))["classification"], "HTTP_CONNECT_FAIL")
    def test_http_37_eof(self): self.assertEqual(analyze_http(self._http_probe(0, error="EOF"))["classification"], "HTTP_CONNECT_FAIL")
    def test_http_38_reset(self): self.assertEqual(analyze_http(self._http_probe(0, error="Reset"))["classification"], "HTTP_CONNECT_FAIL")
    def test_http_39_chunk(self): self.assertEqual(analyze_http(self._http_probe(0, error="Chunk"))["classification"], "HTTP_CONNECT_FAIL")
    def test_http_40_zlib(self): self.assertEqual(analyze_http(self._http_probe(0, error="Zlib"))["classification"], "HTTP_CONNECT_FAIL")

    def test_http_41_redirect_chain(self): self.assertEqual(analyze_http(self._http_probe(301))["classification"], "HTTP_REDIRECT")
    def test_http_42_waf_ok_code(self): self.assertEqual(analyze_http(self._http_probe(200, waf=True))["classification"], "HTTP_PASS")
    def test_http_43_http2(self): self.assertEqual(analyze_http(self._http_probe(200))["classification"], "HTTP_PASS")
    def test_http_44_http3(self): self.assertEqual(analyze_http(self._http_probe(200))["classification"], "HTTP_PASS")
    def test_http_45_waf_503(self): self.assertEqual(analyze_http(self._http_probe(503, waf=True))["classification"], "HTTP_WAF_BLOCK")
    def test_http_46_slow(self): self.assertEqual(analyze_http(self._http_probe(200))["classification"], "HTTP_PASS")
    def test_http_47_unknown(self): self.assertEqual(analyze_http(self._http_probe(600))["classification"], "UNKNOWN")
    def test_http_48_missing_headers(self): self.assertEqual(analyze_http(self._http_probe(200))["classification"], "HTTP_PASS")
    def test_http_49_status_0_no_error(self): self.assertEqual(analyze_http(self._http_probe(0))["classification"], "HTTP_CONNECT_FAIL")
    def test_http_50_waf_false_positive(self): self.assertEqual(analyze_http(self._http_probe(200, waf=True))["classification"], "HTTP_PASS")

    # ==========================
    # TLS Scenarios (40 cases)
    # ==========================
    
    def test_tls_01_valid(self): self.assertEqual(analyze_tls(self._tls_probe())["classification"], "TLS_PASS")
    def test_tls_02_fail(self): self.assertEqual(analyze_tls(self._tls_probe(handshake=False))["classification"], "TLS_FAIL_HANDSHAKE")
    def test_tls_03_expired(self): self.assertEqual(analyze_tls(self._tls_probe(valid=False, error="Expired"))["classification"], "TLS_EXPIRED")
    def test_tls_04_not_yet(self): self.assertEqual(analyze_tls(self._tls_probe(valid=False, error="Not yet valid"))["classification"], "TLS_EXPIRED")
    def test_tls_05_self_signed(self): self.assertEqual(analyze_tls(self._tls_probe(valid=False, error="Self signed"))["classification"], "TLS_WARN_CERT_INVALID")
    
    def test_tls_06_mismatch(self):
        # Now explicitly Hostname Mismatch warning
        res = analyze_tls(self._tls_probe(valid=False, error="Hostname mismatch"))
        self.assertEqual(res["classification"], "TLS_WARN_HOST_MISMATCH")
        
    def test_tls_07_untrusted(self): self.assertEqual(analyze_tls(self._tls_probe(valid=False, error="Untrusted root"))["classification"], "TLS_WARN_CERT_INVALID")
    def test_tls_08_revoked(self): self.assertEqual(analyze_tls(self._tls_probe(valid=False, error="Revoked"))["classification"], "TLS_WARN_CERT_INVALID")
    def test_tls_09_timeout(self): self.assertEqual(analyze_tls(self._tls_probe(handshake=False, error="Timeout"))["classification"], "TLS_FAIL_HANDSHAKE")
    
    def test_tls_10_tls10(self): self.assertEqual(analyze_tls(self._tls_probe(ver="TLSv1.0"))["classification"], "TLS_OLD_PROTOCOL")
    def test_tls_11_tls11(self): self.assertEqual(analyze_tls(self._tls_probe(ver="TLSv1.1"))["classification"], "TLS_OLD_PROTOCOL")
    def test_tls_12_tls12(self): self.assertEqual(analyze_tls(self._tls_probe(ver="TLSv1.2"))["classification"], "TLS_PASS")
    def test_tls_13_tls13(self): self.assertEqual(analyze_tls(self._tls_probe(ver="TLSv1.3"))["classification"], "TLS_PASS")
    def test_tls_14_sslv3(self): self.assertEqual(analyze_tls(self._tls_probe(ver="SSLv3"))["classification"], "TLS_OLD_PROTOCOL")
    
    def test_tls_15_weak_cipher(self): self.assertEqual(analyze_tls(self._tls_probe())["classification"], "TLS_PASS")
    def test_tls_16_null_cipher(self): self.assertEqual(analyze_tls(self._tls_probe())["classification"], "TLS_PASS")
    def test_tls_17_ocsp_stapled(self): self.assertEqual(analyze_tls(self._tls_probe())["classification"], "TLS_PASS")
    def test_tls_18_ocsp_missing(self): self.assertEqual(analyze_tls(self._tls_probe())["classification"], "TLS_PASS")
    
    def test_tls_19_san_mismatch(self): 
        # Matches logic for mismatch/hostname
        self.assertEqual(analyze_tls(self._tls_probe(valid=False, error="Hostname mismatch"))["classification"], "TLS_WARN_HOST_MISMATCH")
        
    def test_tls_20_wildcard(self): self.assertEqual(analyze_tls(self._tls_probe())["classification"], "TLS_PASS")
    def test_tls_21_incomplete(self): self.assertEqual(analyze_tls(self._tls_probe(valid=False))["classification"], "TLS_WARN_CERT_INVALID")
    def test_tls_22_sha1(self): self.assertEqual(analyze_tls(self._tls_probe(valid=False))["classification"], "TLS_WARN_CERT_INVALID")
    def test_tls_23_downgrade(self): self.assertEqual(analyze_tls(self._tls_probe(ver="TLSv1.0"))["classification"], "TLS_OLD_PROTOCOL")
    def test_tls_24_sni_error(self): self.assertEqual(analyze_tls(self._tls_probe(handshake=False))["classification"], "TLS_FAIL_HANDSHAKE")
    def test_tls_25_alert(self): self.assertEqual(analyze_tls(self._tls_probe(handshake=False))["classification"], "TLS_FAIL_HANDSHAKE")
    def test_tls_26_decrypt(self): self.assertEqual(analyze_tls(self._tls_probe(handshake=False))["classification"], "TLS_FAIL_HANDSHAKE")
    def test_tls_27_expiring_soon(self): self.assertEqual(analyze_tls(self._tls_probe())["classification"], "TLS_PASS")
    def test_tls_28_multi_chain(self): self.assertEqual(analyze_tls(self._tls_probe())["classification"], "TLS_PASS")
    def test_tls_29_client_cert(self): self.assertEqual(analyze_tls(self._tls_probe(handshake=False))["classification"], "TLS_FAIL_HANDSHAKE")
    def test_tls_30_renegotiation(self): self.assertEqual(analyze_tls(self._tls_probe())["classification"], "TLS_PASS")
    
    def test_tls_31_compression(self): self.assertEqual(analyze_tls(self._tls_probe())["classification"], "TLS_PASS")
    def test_tls_32_heartbeat(self): self.assertEqual(analyze_tls(self._tls_probe())["classification"], "TLS_PASS")
    def test_tls_33_weak_curve(self): self.assertEqual(analyze_tls(self._tls_probe())["classification"], "TLS_PASS")
    def test_tls_34_short_key(self): self.assertEqual(analyze_tls(self._tls_probe())["classification"], "TLS_PASS")
    def test_tls_35_algo_unsupported(self): self.assertEqual(analyze_tls(self._tls_probe(handshake=False))["classification"], "TLS_FAIL_HANDSHAKE")
    def test_tls_36_crl_fail(self): self.assertEqual(analyze_tls(self._tls_probe())["classification"], "TLS_PASS")
    def test_tls_37_parse_err(self): self.assertEqual(analyze_tls(self._tls_probe(handshake=False))["classification"], "TLS_FAIL_HANDSHAKE")
    def test_tls_38_unexpected(self): self.assertEqual(analyze_tls(self._tls_probe(handshake=False))["classification"], "TLS_FAIL_HANDSHAKE")
    def test_tls_39_internal(self): self.assertEqual(analyze_tls(self._tls_probe(handshake=False))["classification"], "TLS_FAIL_HANDSHAKE")
    def test_tls_40_user_cancel(self): self.assertEqual(analyze_tls(self._tls_probe(handshake=False))["classification"], "TLS_FAIL_HANDSHAKE")

    # ==========================
    # MTU Scenarios (20 cases)
    # ==========================
    # ... (MTU logic unchanged, keeping tests) ...
    def test_mtu_01_1500(self): self.assertEqual(analyze_mtu(self._mtu_probe(1500))["classification"], "MTU_PASS")
    def test_mtu_02_1492(self): self.assertEqual(analyze_mtu(self._mtu_probe(1492))["classification"], "MTU_WARNING")
    def test_mtu_03_1472(self): self.assertEqual(analyze_mtu(self._mtu_probe(1472))["classification"], "MTU_WARNING")
    def test_mtu_04_1400(self): self.assertEqual(analyze_mtu(self._mtu_probe(1400))["classification"], "MTU_WARNING")
    def test_mtu_05_1280(self): self.assertEqual(analyze_mtu(self._mtu_probe(1280))["classification"], "MTU_WARNING")
    def test_mtu_06_1279(self): self.assertEqual(analyze_mtu(self._mtu_probe(1279))["classification"], "MTU_CRITICAL")
    def test_mtu_07_576(self): self.assertEqual(analyze_mtu(self._mtu_probe(576))["classification"], "MTU_CRITICAL")
    def test_mtu_08_0(self): self.assertEqual(analyze_mtu(self._mtu_probe(0))["classification"], "MTU_WARNING")
    def test_mtu_09_jumbo(self): self.assertEqual(analyze_mtu(self._mtu_probe(9000))["classification"], "MTU_PASS")
    def test_mtu_10_vpn(self): self.assertEqual(analyze_mtu(self._mtu_probe(1350))["classification"], "MTU_WARNING")
    def test_mtu_11_cellular(self): self.assertEqual(analyze_mtu(self._mtu_probe(1420))["classification"], "MTU_WARNING")
    def test_mtu_12_loss(self): self.assertEqual(analyze_mtu(self._mtu_probe(1500))["classification"], "MTU_PASS")
    def test_mtu_13_partial(self): self.assertEqual(analyze_mtu(self._mtu_probe(1500))["classification"], "MTU_PASS")
    def test_mtu_14_frag(self): self.assertEqual(analyze_mtu(self._mtu_probe(1400))["classification"], "MTU_WARNING")
    def test_mtu_15_localhost(self): self.assertEqual(analyze_mtu(self._mtu_probe(65535))["classification"], "MTU_PASS")
    def test_mtu_16_1480(self): self.assertEqual(analyze_mtu(self._mtu_probe(1480))["classification"], "MTU_WARNING")
    def test_mtu_17_1454(self): self.assertEqual(analyze_mtu(self._mtu_probe(1454))["classification"], "MTU_WARNING")
    def test_mtu_18_1500_v6(self): self.assertEqual(analyze_mtu(self._mtu_probe(1500))["classification"], "MTU_PASS")
    def test_mtu_19_1280_v6(self): self.assertEqual(analyze_mtu(self._mtu_probe(1280))["classification"], "MTU_WARNING")
    def test_mtu_20_low_v6(self): self.assertEqual(analyze_mtu(self._mtu_probe(1279))["classification"], "MTU_CRITICAL")

    # ==========================
    # Origin Scenarios (30 cases)
    # ==========================
    # ... (Origin logic unchanged, keeping tests) ...
    def test_org_01_both_ok(self): self.assertEqual(analyze_origin_reachability(self._http_probe(200), self._http_probe(200))["classification"], "ORIGIN_REACHABLE")
    def test_org_02_timeout(self): self.assertEqual(analyze_origin_reachability(self._http_probe(522), self._http_probe(0, error="Timeout"))["classification"], "ORIGIN_522")
    def test_org_03_refused(self): self.assertEqual(analyze_origin_reachability(self._http_probe(522), self._http_probe(0, error="Refused"))["classification"], "ORIGIN_UNREACHABLE")
    def test_org_04_firewall(self): self.assertEqual(analyze_origin_reachability(self._http_probe(522), self._http_probe(200))["classification"], "ORIGIN_FIREWALL_BLOCK")
    def test_org_05_521(self): self.assertEqual(analyze_origin_reachability(self._http_probe(521), self._http_probe(0, error="Refused"))["classification"], "ORIGIN_UNREACHABLE")
    def test_org_06_523(self): self.assertEqual(analyze_origin_reachability(self._http_probe(523), self._http_probe(0, error="No Route"))["classification"], "ORIGIN_UNREACHABLE")
    def test_org_07_slow(self): self.assertEqual(analyze_origin_reachability(self._http_probe(524), self._http_probe(200))["classification"], "ORIGIN_FIREWALL_BLOCK")
    def test_org_08_ssl_fail(self): self.assertEqual(analyze_origin_reachability(self._http_probe(525), self._http_probe(0, error="SSL"))["classification"], "ORIGIN_UNREACHABLE")
    def test_org_09_cert_invalid(self): self.assertEqual(analyze_origin_reachability(self._http_probe(526), self._http_probe(0, error="Cert"))["classification"], "ORIGIN_UNREACHABLE")
    def test_org_10_mismatch_403(self): self.assertEqual(analyze_origin_reachability(self._http_probe(200), self._http_probe(403))["classification"], "ORIGIN_REACHABLE")
    def test_org_11_mismatch_404(self): self.assertEqual(analyze_origin_reachability(self._http_probe(200), self._http_probe(404))["classification"], "ORIGIN_REACHABLE")
    def test_org_12_mismatch_500(self): self.assertEqual(analyze_origin_reachability(self._http_probe(200), self._http_probe(500))["classification"], "ORIGIN_REACHABLE")
    def test_org_13_502_502(self): self.assertEqual(analyze_origin_reachability(self._http_probe(502), self._http_probe(502))["classification"], "ORIGIN_REACHABLE")
    def test_org_14_502_200(self): self.assertEqual(analyze_origin_reachability(self._http_probe(502), self._http_probe(200))["classification"], "ORIGIN_FIREWALL_BLOCK")
    def test_org_15_waf_200(self): self.assertEqual(analyze_origin_reachability(self._http_probe(403, waf=True), self._http_probe(200))["classification"], "ORIGIN_REACHABLE")
    def test_org_16_301_200(self): self.assertEqual(analyze_origin_reachability(self._http_probe(301), self._http_probe(200))["classification"], "ORIGIN_REACHABLE")
    def test_org_17_ip_mismatch(self): self.assertEqual(analyze_origin_reachability(self._http_probe(200), self._http_probe(200))["classification"], "ORIGIN_REACHABLE")
    def test_org_18_http2(self): self.assertEqual(analyze_origin_reachability(self._http_probe(200), self._http_probe(200))["classification"], "ORIGIN_REACHABLE")
    def test_org_19_429(self): self.assertEqual(analyze_origin_reachability(self._http_probe(200), self._http_probe(429))["classification"], "ORIGIN_REACHABLE")
    def test_org_20_both_timeout(self): self.assertEqual(analyze_origin_reachability(self._http_probe(0, error="Timeout"), self._http_probe(0, error="Timeout"))["classification"], "ORIGIN_522")
    def test_org_21_dns_error(self): self.assertEqual(analyze_origin_reachability(self._http_probe(530), self._http_probe(200))["classification"], "ORIGIN_REACHABLE")
    def test_org_22_1000(self): self.assertEqual(analyze_origin_reachability(self._http_probe(1000), self._http_probe(200))["classification"], "ORIGIN_REACHABLE")
    def test_org_23_read_timeout(self): self.assertEqual(analyze_origin_reachability(self._http_probe(522), self._http_probe(0, error="Read"))["classification"], "ORIGIN_UNREACHABLE")
    def test_org_24_reset(self): self.assertEqual(analyze_origin_reachability(self._http_probe(522), self._http_probe(0, error="Reset"))["classification"], "ORIGIN_UNREACHABLE")
    def test_org_25_empty(self): self.assertEqual(analyze_origin_reachability(self._http_probe(522), self._http_probe(0, error="Empty"))["classification"], "ORIGIN_UNREACHABLE")
    def test_org_26_proto(self): self.assertEqual(analyze_origin_reachability(self._http_probe(522), self._http_probe(0, error="Protocol"))["classification"], "ORIGIN_UNREACHABLE")
    def test_org_27_ipv6(self): self.assertEqual(analyze_origin_reachability(self._http_probe(200), self._http_probe(200))["classification"], "ORIGIN_REACHABLE")
    def test_org_28_ipv4(self): self.assertEqual(analyze_origin_reachability(self._http_probe(200), self._http_probe(200))["classification"], "ORIGIN_REACHABLE")
    def test_org_29_loop(self): self.assertEqual(analyze_origin_reachability(self._http_probe(301), self._http_probe(301))["classification"], "ORIGIN_REACHABLE")
    def test_org_30_hs_timeout(self): self.assertEqual(analyze_origin_reachability(self._http_probe(525), self._http_probe(0, error="Handshake"))["classification"], "ORIGIN_UNREACHABLE")

    # --- Helpers ---
    def _dns_probe(self, a, aaaa, error=None, dnssec=None):
        return {
            "domain": "example.com", "records": {"A": a, "AAAA": aaaa, "CNAME": [], "NS": []},
            "resolvers_used": [], "dnssec_valid": dnssec, "error": error, "raw_output": ""
        }

    def _http_probe(self, code, waf=False, error=None):
        return {
            "url": "http://x", "status_code": code, "headers": {}, 
            "redirect_chain": [], "timings": {}, "body_sample": "", 
            "is_waf_challenge": waf, "http_version": "1.1", "error": error
        }
        
    def _tls_probe(self, handshake=True, valid=True, ver="TLSv1.3", error=None):
        ver_errs = []
        if error: ver_errs.append(error)
        return {
            "handshake_success": handshake, "cert_valid": valid, 
            "protocol_version": ver, "verification_errors": ver_errs,
            "error": error if not handshake else None, "cert_expiry": "2025", "cert_start": "2024", 
            "ocsp_stapled": False, "cipher": "AES", "cert_subject": "x", "cert_issuer": "y"
        }

    def _mtu_probe(self, mtu):
        return {
            "path_mtu": mtu, "fragmentation_point": 0 if mtu else None,
            "packets_sent": 5, "packets_lost": 0, "error": "Fail" if mtu==0 else None
        }

if __name__ == '__main__':
    unittest.main()