# Refactoring Plan: ASN & Terminal Formatting

## 1. ASN/Whois Logic Refactor Path

Currently, ASN/Whois logic is embedded within `step_dns` in `cfdiag/network.py`. To align with the Probe-Analyze-Present architecture, this should be split:

### Phase 1: Create Probe
*   **Function**: `probe_asn(ip: str) -> ProbeASNResult`
*   **Location**: `cfdiag/probes.py`
*   **Output Schema**:
    ```python
    class ProbeASNResult(TypedDict):
        ip: str
        asn: str | None      # e.g. "13335"
        org: str | None      # e.g. "CLOUDFLARENET"
        country: str | None  # e.g. "US"
        error: str | None
    ```
*   **Implementation**: encapsulate the existing `dig +short -t TXT {rev_ip}.origin.asn.cymru.com` logic here.

### Phase 2: Create Analysis
*   **Function**: `analyze_asn(probe: ProbeASNResult) -> AnalysisResult`
*   **Location**: `cfdiag/analysis.py`
*   **Logic**:
    *   If `asn` is present: `ASN_FOUND` (PASS/INFO)
    *   If `error`: `ASN_FAIL` (WARNING - non-critical)

### Phase 3: Create Presenter
*   **Function**: `step_asn(ip: str)`
*   **Location**: `cfdiag/network.py`
*   **Logic**: Calls `probe_asn`, then `analyze_asn`, then prints result using `print_success` / `print_warning`.
*   **Integration**: `step_dns` calls `step_asn` after successful resolution.

## 2. Terminal Formatting Rules

To prevent terminal corruption:

1.  **Persistent Formatting**:
    *   Use context managers (e.g. `with console_lock:`) for thread-safe printing.
    *   Always append `{Colors.ENDC}` to any string constructed with `Colors.*`.

2.  **Ephemeral Formatting**:
    *   For interactive modes like MTR, clear screen sequences (`cls`/`clear`) must be followed by a full redraw.
    *   Ensure `KeyboardInterrupt` handlers print a final newline and reset code.

3.  **Audit**:
    *   Check all `f-strings` containing `Colors.*`.
    *   Ensure `cfdiag/reporting.py` helper functions (`print_success`, etc.) automatically append `ENDC`.
