from typing import TypedDict, List, Dict, Optional, Any, Union
from enum import Enum

class ProbeDNSResult(TypedDict):
    domain: str
    records: Dict[str, List[str]]  # "A", "AAAA", "CNAME", "NS"
    resolvers_used: List[str]
    dnssec_valid: Optional[bool]
    raw_output: str
    error: Optional[str]

class ProbeHTTPResult(TypedDict):
    url: str
    status_code: int
    headers: Dict[str, str]        # Normalized lowercase keys
    redirect_chain: List[str]
    timings: Dict[str, float]      # connect, ttfb, total, namelookup
    body_snippet: str              # Renamed from body_sample per spec
    is_waf_challenge: bool
    http_version: str              # "1.1", "2", "3"
    error: Optional[str]

class ProbeTLSResult(TypedDict):
    handshake_success: bool
    protocol_version: Optional[str]
    cipher: Optional[str]
    cert_valid: bool
    cert_subject: Optional[str]
    cert_issuer: Optional[str]
    cert_expiry: Optional[str]      # ISO 8601 String
    cert_start: Optional[str]       # ISO 8601 String
    verification_errors: List[str]
    ocsp_stapled: bool
    error: Optional[str]

class ProbeMTUResult(TypedDict):
    path_mtu: int
    fragmentation_point: Optional[int]
    packets_sent: int
    packets_lost: int
    error: Optional[str]

class ProbeOriginResult(TypedDict):
    edge_probe: ProbeHTTPResult
    origin_probe: ProbeHTTPResult
    origin_ip_used: str
    error: Optional[str]

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"
    PASS = "PASS"

class AnalysisResult(TypedDict):
    status: Severity
    classification: str
    human_reason: str
    recommendations: List[str]
    meta: Dict[str, Any]

class FullReport(TypedDict):
    meta: Dict[str, Any]
    summary: Dict[str, Optional[AnalysisResult]]
    final_classification: Severity
    reason_codes: List[str]
    recommendations: List[str]
