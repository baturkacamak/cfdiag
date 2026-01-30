from enum import Enum, auto
from typing import Any, Dict, List, Optional


class Severity(Enum):
    """
    Generic severity levels for diagnostics and analysis output.
    Kept minimal to satisfy formatting and reporting tests.
    """

    PASS = auto()
    WARN = auto()
    FAIL = auto()
    INFO = auto()
    CRITICAL = auto()  # Alias for FAIL in critical cases
    ERROR = auto()  # Alias for FAIL in error cases


AnalysisMeta = Dict[str, Any]
Recommendations = List[str]


class HTTPClassification(str, Enum):
    HTTP_PASS = "HTTP_PASS"
    HTTP_WARN = "HTTP_WARN"
    HTTP_FAIL = "HTTP_FAIL"


class TLSClassification(str, Enum):
    TLS_PASS = "TLS_PASS"
    TLS_WARN = "TLS_WARN"
    TLS_FAIL = "TLS_FAIL"


class HTTPAnalysisResult(Dict[str, Any]):
    """
    Typed dictionary-style object used by tests via keys like:
      - status: Severity
      - human_reason: str
      - classification: HTTPClassification
      - meta: AnalysisMeta
      - recommendations: Recommendations
    """

    status: Severity
    human_reason: str
    classification: HTTPClassification
    meta: AnalysisMeta
    recommendations: Recommendations


class TLSAnalysisResult(Dict[str, Any]):
    """
    Similar shape for TLS analysis if needed in the future.
    """

    status: Severity
    human_reason: str
    classification: TLSClassification
    meta: AnalysisMeta
    recommendations: Recommendations


# Probe Result Types (used by probes.py)
ProbeDNSResult = Dict[str, Any]  # domain, records, resolvers_used, dnssec_valid, error, raw_output
ProbeHTTPResult = Dict[str, Any]  # url, status_code, headers, redirect_chain, timings, body_sample, is_waf_challenge, http_version, error
ProbeTLSResult = Dict[str, Any]  # handshake_success, cert_valid, protocol_version, cert_expiry, cert_start, cert_issuer, verification_errors, ocsp_stapled, cipher, cert_subject, error
ProbeMTUResult = Dict[str, Any]  # passed_mtu, fail_point, packets_sent, packets_lost, error
ProbeOriginResult = Dict[str, Any]  # edge_probe, origin_probe, error
ProbeCDNReachabilityResult = Dict[str, Any]  # edge, origin, error
ProbeASNResult = Dict[str, Any]  # ip, asn, country, error, raw_output

# Analysis Result Type (used by analysis.py)
AnalysisResult = Dict[str, Any]  # status, classification, human_reason, meta, recommendations

