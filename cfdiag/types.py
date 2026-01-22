from typing import TypedDict, List, Dict, Optional, Any, Union
from enum import Enum

class ProbeDNSResult(TypedDict):
    domain: str
    records: Dict[str, List[str]]  # "A", "AAAA", "CNAME", "NS"
    resolvers_used: List[str]
    dnssec_valid: Optional[bool]
    error: Optional[str]
    raw_output: str

class ProbeHTTPResult(TypedDict):
    url: str
    status_code: int
    headers: Dict[str, str]        # Normalized lowercase keys
    redirect_chain: List[str]
    timings: Dict[str, float]      # "namelookup", "connect", "ttfb", "total"
    http_version: str              # "1.1", "2", "3"
    body_sample: str
    is_waf_challenge: bool
    error: Optional[str]

class ProbeTLSResult(TypedDict):
    handshake_success: bool
    cert_valid: bool
    protocol_version: Optional[str]
    cert_expiry: Optional[str]      # ISO 8601 String
    cert_start: Optional[str]       # ISO 8601 String
    cert_issuer: str
    verification_errors: List[str]
    ocsp_stapled: bool
    cipher: str
    cert_subject: str
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
    error: Optional[str]

class ProbeASNResult(TypedDict):
    ip: str
    asn: Optional[str]
    country: Optional[str]
    error: Optional[str]
    raw_output: str

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
