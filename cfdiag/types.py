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

