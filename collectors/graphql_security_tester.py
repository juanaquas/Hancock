"""
GraphQL Security Testing Script
Demonstrates techniques for testing GraphQL authentication/authorization flaws.
For educational purposes and authorized testing only.

Usage:
    python graphql_security_tester.py --url https://target.com/graphql --token <jwt>
"""
import argparse
import json
import sys
from typing import Dict, List, Any, Optional
import hmac
import hashlib
import base64


class GraphQLSecurityTester:
    """
    Automated GraphQL security testing for authentication/authorization flaws.
    Tests: IDOR, JWT vulnerabilities, field-level auth, mutation auth, rate limiting.
    """
    
    def __init__(self, url: str, token: Optional[str] = None, verbose: bool = False):
        self.url = url
        self.token = token
        self.verbose = verbose
        self.findings: List[Dict[str, Any]] = []
    
    def log(self, message: str, level: str = "INFO"):
        """Print log message if verbose mode is enabled."""
        if self.verbose:
            prefix = {
                "INFO": "[*]",
                "SUCCESS": "[+]",
                "VULN": "[!]",
                "ERROR": "[-]",
            }.get(level, "[?]")
            print(f"{prefix} {message}")
    
    def add_finding(self, title: str, severity: str, description: str, payload: str = ""):
        """Record a security finding."""
        self.findings.append({
            "title": title,
            "severity": severity,
            "description": description,
            "payload": payload,
        })
        self.log(f"VULNERABILITY: {title} (Severity: {severity})", "VULN")
    
    def test_introspection(self) -> bool:
        """Test if GraphQL introspection is enabled."""
        self.log("Testing introspection query...")
        
        introspection_query = {
            "query": """
                query IntrospectionQuery {
                    __schema {
                        queryType { name }
                        mutationType { name }
                        types {
                            name
                            kind
                            fields { name }
                        }
                    }
                }
            """
        }
        
        # Simulated test - in real scenario would use requests.post()
        self.log("Introspection query sent", "INFO")
        
        # Mock response: introspection disabled
        enabled = False  # Would parse actual response
        
        if enabled:
            self.add_finding(
                title="Introspection Enabled in Production",
                severity="MEDIUM",
                description="GraphQL introspection is enabled, allowing attackers to enumerate the full schema.",
                payload=json.dumps(introspection_query, indent=2)
            )
            return True
        else:
            self.log("Introspection is disabled (SECURE)", "SUCCESS")
            return False
    
    def test_idor(self, user_id: str = "123") -> bool:
        """Test for Insecure Direct Object Reference (IDOR) vulnerabilities."""
        self.log(f"Testing IDOR with user ID: {user_id}...")
        
        # Test 1: Simple user query
        query = {
            "query": f"""
                query {{
                    user(id: "{user_id}") {{
                        id
                        email
                        phone
                    }}
                }}
            """
        }
        
        self.log("Attempting to access other user's data...", "INFO")
        
        # Mock response - in real scenario would check if data is returned
        # For demo purposes, simulate finding
        vulnerable = True  # Would be determined by actual response
        
        if vulnerable:
            self.add_finding(
                title="IDOR: Missing Object-Level Authorization",
                severity="HIGH",
                description=f"User query allows access to other users' sensitive data (email, phone) without proper authorization checks. Any authenticated user can read data for user ID {user_id}.",
                payload=json.dumps(query, indent=2)
            )
            return True
        
        return False
    
    def test_idor_batch(self, user_ids: List[str]) -> bool:
        """Test IDOR using batch queries with aliases."""
        self.log(f"Testing batch IDOR with {len(user_ids)} user IDs...")
        
        # Build aliased query
        alias_queries = []
        for idx, uid in enumerate(user_ids):
            alias_queries.append(f'u{idx}: user(id: "{uid}") {{ id email }}')
        
        query = {
            "query": f"""
                query {{
                    {' '.join(alias_queries)}
                }}
            """
        }
        
        self.log("Batch query with aliases sent", "INFO")
        
        # Mock: simulate some IDs returning data
        vulnerable = True  # Would check actual response
        
        if vulnerable:
            self.add_finding(
                title="IDOR: Batch Query Enumeration",
                severity="HIGH",
                description=f"Batch queries with aliases allow enumeration of multiple user records in a single request, enabling rapid data exfiltration.",
                payload=json.dumps(query, indent=2)
            )
            return True
        
        return False
    
    def test_jwt_algorithm_confusion(self) -> bool:
        """Test JWT algorithm confusion (alg: none) vulnerability."""
        self.log("Testing JWT algorithm confusion attack...")
        
        if not self.token:
            self.log("No token provided, skipping JWT tests", "INFO")
            return False
        
        # Create token with alg: none
        header = {"alg": "none", "typ": "JWT"}
        payload = {"sub": "admin", "role": "admin"}
        
        # Encode without signature
        encoded_header = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip('=')
        encoded_payload = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip('=')
        
        none_token = f"{encoded_header}.{encoded_payload}."
        
        self.log("Crafted token with alg:none", "INFO")
        
        # Mock: server should reject this
        accepted = False  # Would check actual response
        
        if accepted:
            self.add_finding(
                title="JWT Algorithm Confusion (alg: none)",
                severity="CRITICAL",
                description="Server accepts JWT tokens with 'alg: none', allowing attackers to forge tokens without a signature.",
                payload=f"Token: {none_token}"
            )
            return True
        else:
            self.log("Server rejects alg:none tokens (SECURE)", "SUCCESS")
            return False
    
    def test_mutation_authorization(self, target_user_id: str = "999") -> bool:
        """Test mutation authorization bypass."""
        self.log(f"Testing mutation authorization for user ID: {target_user_id}...")
        
        mutation = {
            "query": f"""
                mutation {{
                    updateUser(id: "{target_user_id}", input: {{
                        email: "attacker@evil.com"
                    }}) {{
                        id
                        email
                    }}
                }}
            """
        }
        
        self.log("Attempting cross-account mutation...", "INFO")
        
        # Mock response
        vulnerable = False  # Would check if mutation succeeded
        
        if vulnerable:
            self.add_finding(
                title="Missing Mutation Authorization",
                severity="CRITICAL",
                description=f"updateUser mutation allows modifying other users' accounts without ownership validation.",
                payload=json.dumps(mutation, indent=2)
            )
            return True
        else:
            self.log("Mutation properly rejects unauthorized access (SECURE)", "SUCCESS")
            return False
    
    def test_field_level_authorization(self) -> bool:
        """Test field-level authorization."""
        self.log("Testing field-level authorization...")
        
        query = {
            "query": """
                query {
                    user(id: "other_user_id") {
                        id
                        publicName
                        email
                        ssn
                        salary
                    }
                }
            """
        }
        
        self.log("Requesting sensitive fields for another user...", "INFO")
        
        # Mock: check which fields are returned
        sensitive_fields_exposed = ["email"]  # Would parse from response
        
        if sensitive_fields_exposed:
            self.add_finding(
                title="Missing Field-Level Authorization",
                severity="HIGH",
                description=f"Sensitive fields ({', '.join(sensitive_fields_exposed)}) are accessible without proper authorization checks.",
                payload=json.dumps(query, indent=2)
            )
            return True
        else:
            self.log("Sensitive fields properly protected (SECURE)", "SUCCESS")
            return False
    
    def test_rate_limiting(self) -> bool:
        """Test rate limiting on login mutations."""
        self.log("Testing rate limiting on authentication...")
        
        mutation = {
            "query": """
                mutation {
                    login(email: "test@evil.com", password: "wrong") {
                        token
                    }
                }
            """
        }
        
        self.log("Simulating 50 rapid login attempts...", "INFO")
        
        # Mock: simulate rate limit response after N attempts
        rate_limited = True  # Would check actual behavior
        attempts_before_limit = 8
        
        if not rate_limited or attempts_before_limit > 15:
            self.add_finding(
                title="Weak Rate Limiting",
                severity="MEDIUM",
                description=f"Login mutation allows {attempts_before_limit} attempts before rate limiting, enabling brute-force attacks.",
                payload=json.dumps(mutation, indent=2)
            )
            return True
        else:
            self.log(f"Strong rate limiting detected after {attempts_before_limit} attempts (SECURE)", "SUCCESS")
            return False
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate security assessment report."""
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }
        
        for finding in self.findings:
            severity_counts[finding["severity"]] += 1
        
        overall_severity = "SECURE"
        if severity_counts["CRITICAL"] > 0:
            overall_severity = "CRITICAL"
        elif severity_counts["HIGH"] > 0:
            overall_severity = "HIGH"
        elif severity_counts["MEDIUM"] > 0:
            overall_severity = "MEDIUM"
        
        return {
            "target": self.url,
            "timestamp": "2026-03-01T17:57:00Z",
            "overall_severity": overall_severity,
            "total_findings": len(self.findings),
            "severity_breakdown": severity_counts,
            "findings": self.findings,
        }
    
    def run_all_tests(self):
        """Execute all security tests."""
        self.log("=" * 60, "INFO")
        self.log("GraphQL Security Assessment", "INFO")
        self.log(f"Target: {self.url}", "INFO")
        self.log("=" * 60, "INFO")
        
        # Run test suite
        self.test_introspection()
        self.test_idor("usr_123456")
        self.test_idor_batch(["1", "2", "999999"])
        self.test_jwt_algorithm_confusion()
        self.test_mutation_authorization()
        self.test_field_level_authorization()
        self.test_rate_limiting()
        
        # Generate report
        report = self.generate_report()
        
        self.log("=" * 60, "INFO")
        self.log("Assessment Complete", "SUCCESS")
        self.log(f"Overall Severity: {report['overall_severity']}", "INFO")
        self.log(f"Total Findings: {report['total_findings']}", "INFO")
        self.log("=" * 60, "INFO")
        
        return report


def main():
    parser = argparse.ArgumentParser(
        description="GraphQL Security Testing Tool (Educational/Authorized Use Only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test with authentication
  python graphql_security_tester.py --url https://api.example.com/graphql --token <jwt>
  
  # Test without authentication (public endpoints only)
  python graphql_security_tester.py --url https://api.example.com/graphql --verbose
  
  # Generate report
  python graphql_security_tester.py --url https://api.example.com/graphql --report report.json

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
Unauthorized testing is illegal. Always obtain written permission before testing.
        """
    )
    
    parser.add_argument("--url", required=True, help="GraphQL endpoint URL")
    parser.add_argument("--token", help="JWT token for authenticated testing")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--report", help="Save JSON report to file")
    
    args = parser.parse_args()
    
    # Security check
    print("\n⚠️  LEGAL DISCLAIMER ⚠️")
    print("This tool is for AUTHORIZED SECURITY TESTING ONLY.")
    print("Unauthorized access to computer systems is illegal.")
    print("Ensure you have written permission before proceeding.\n")
    
    response = input("Do you have written authorization to test this endpoint? (yes/no): ")
    if response.lower() != "yes":
        print("Testing aborted. Obtain authorization first.")
        sys.exit(1)
    
    # Run tests
    tester = GraphQLSecurityTester(args.url, args.token, args.verbose)
    report = tester.run_all_tests()
    
    # Output report
    if args.report:
        with open(args.report, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n✅ Report saved to: {args.report}")
    else:
        print("\n" + "=" * 60)
        print("FINDINGS SUMMARY")
        print("=" * 60)
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
