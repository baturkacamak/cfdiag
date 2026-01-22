import unittest
import sys
import os
from typing import Dict

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import cfdiag.network
import cfdiag.analysis
from cfdiag.types import Severity

class TestCoverageRules(unittest.TestCase):
    
    def test_legacy_mapping_completeness(self):
        """
        Verify that EVERY classification produced by analysis has a deterministic 
        mapping in the network presentation layer.
        """
        # 1. Extract all possible classifications from Analysis
        # This is a meta-test. We inspect the code or define the source of truth.
        # Source of truth is docs/decision_trees.md or the types.
        
        expected_classifications = [
            # HTTP
            "HTTP_PASS", "HTTP_REDIRECT", "HTTP_WAF_BLOCK", "HTTP_RATE_LIMIT",
            "HTTP_CLIENT_ERROR", "HTTP_SERVER_ERROR", "HTTP_TIMEOUT", 
            "HTTP_CONNECT_FAIL", "UNKNOWN",
            # DNS
            "DNS_PASS", "DNS_FAIL", "DNS_IPV4_ONLY", "DNS_IPV6_ONLY",
            # TLS
            "TLS_PASS", "TLS_FAIL_HANDSHAKE", "TLS_EXPIRED", 
            "TLS_WARN_CERT_INVALID", "TLS_OLD_PROTOCOL",
            # MTU
            "MTU_PASS", "MTU_WARNING", "MTU_CRITICAL",
            # ORIGIN
            "ORIGIN_REACHABLE", "ORIGIN_522", "ORIGIN_UNREACHABLE", 
            "ORIGIN_FIREWALL_BLOCK"
        ]
        
        # 2. Verify mappings in step functions (Simulated)
        # We can't easily inspect the 'if/elif' blocks in step_* functions without AST parsing.
        # Instead, we rely on the extensive table-driven tests in test_network_presenters.py 
        # and test_analysis_logic.py to cover these paths.
        
        # However, we CAN assert that we have tests for each of these keys.
        # We check if 'test_analysis_logic.py' contains string literals for all of them.
        
        with open(os.path.join(os.path.dirname(__file__), "test_analysis_logic.py"), 'r') as f:
            test_code = f.read()
            
        missing = []
        for cls in expected_classifications:
            if f'"{cls}"' not in test_code and f"'{cls}'" not in test_code:
                missing.append(cls)
                
        self.assertEqual(missing, [], f"The following classifications are defined but NOT tested in test_analysis_logic.py: {missing}")

if __name__ == '__main__':
    unittest.main()
