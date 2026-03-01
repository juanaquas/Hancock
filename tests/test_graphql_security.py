"""
Tests for GraphQL Security Knowledge Base
"""
import json
import unittest
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from collectors.graphql_security_kb import collect, KB, HANCOCK_SYSTEM


class TestGraphQLSecurityKB(unittest.TestCase):
    """Test cases for GraphQL security knowledge base."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.kb_data = KB
        self.output_file = Path(__file__).parent.parent / "data" / "raw_graphql_security_kb.json"
    
    def test_kb_has_entries(self):
        """Test that KB contains entries."""
        self.assertGreater(len(self.kb_data), 0, "KB should have at least one entry")
    
    def test_kb_entry_structure(self):
        """Test that each KB entry has required fields."""
        for entry in self.kb_data:
            self.assertIn("category", entry, "Entry should have 'category' field")
            self.assertIn("user", entry, "Entry should have 'user' field")
            self.assertIn("assistant", entry, "Entry should have 'assistant' field")
    
    def test_kb_categories(self):
        """Test that all entries have graphql_auth category."""
        for entry in self.kb_data:
            self.assertEqual(entry["category"], "graphql_auth", 
                           "All entries should be in graphql_auth category")
    
    def test_kb_content_quality(self):
        """Test that KB entries have substantial content."""
        for entry in self.kb_data:
            # User questions should be clear and concise
            self.assertGreater(len(entry["user"]), 10, 
                             "User question should be at least 10 characters")
            self.assertLess(len(entry["user"]), 500, 
                          "User question should be less than 500 characters")
            
            # Assistant responses should be detailed
            self.assertGreater(len(entry["assistant"]), 100, 
                             "Assistant response should be at least 100 characters")
    
    def test_kb_covers_idor(self):
        """Test that KB covers IDOR vulnerabilities."""
        idor_found = False
        for entry in self.kb_data:
            if "IDOR" in entry["user"] or "IDOR" in entry["assistant"]:
                idor_found = True
                break
        self.assertTrue(idor_found, "KB should cover IDOR vulnerabilities")
    
    def test_kb_covers_jwt(self):
        """Test that KB covers JWT vulnerabilities."""
        jwt_found = False
        for entry in self.kb_data:
            if "JWT" in entry["user"] or "JWT" in entry["assistant"]:
                jwt_found = True
                break
        self.assertTrue(jwt_found, "KB should cover JWT vulnerabilities")
    
    def test_kb_covers_mutations(self):
        """Test that KB covers mutation authorization."""
        mutation_found = False
        for entry in self.kb_data:
            if "mutation" in entry["user"].lower() or "mutation" in entry["assistant"].lower():
                mutation_found = True
                break
        self.assertTrue(mutation_found, "KB should cover mutation authorization")
    
    def test_kb_includes_code_examples(self):
        """Test that KB includes code examples."""
        code_examples_found = False
        for entry in self.kb_data:
            if "```" in entry["assistant"]:
                code_examples_found = True
                break
        self.assertTrue(code_examples_found, "KB should include code examples")
    
    def test_system_prompt(self):
        """Test system prompt is properly configured."""
        self.assertIsNotNone(HANCOCK_SYSTEM, "System prompt should be defined")
        self.assertGreater(len(HANCOCK_SYSTEM), 50, "System prompt should be detailed")
        self.assertIn("Hancock", HANCOCK_SYSTEM, "System prompt should mention Hancock")
        self.assertIn("authorized", HANCOCK_SYSTEM.lower(), 
                     "System prompt should emphasize authorized testing")
    
    def test_collect_generates_file(self):
        """Test that collect() generates output file."""
        count = collect()
        self.assertGreater(count, 0, "collect() should return count > 0")
        self.assertTrue(self.output_file.exists(), 
                       f"Output file should exist at {self.output_file}")
    
    def test_output_file_structure(self):
        """Test output file has correct JSON structure."""
        if not self.output_file.exists():
            collect()
        
        with open(self.output_file, 'r') as f:
            data = json.load(f)
        
        self.assertIn("source", data, "Output should have 'source' field")
        self.assertIn("system", data, "Output should have 'system' field")
        self.assertIn("pairs", data, "Output should have 'pairs' field")
        self.assertIn("count", data, "Output should have 'count' field")
        
        self.assertEqual(data["source"], "graphql_security_kb")
        self.assertIsInstance(data["pairs"], list)
        self.assertEqual(len(data["pairs"]), data["count"])
    
    def test_security_best_practices_coverage(self):
        """Test that KB covers essential security best practices."""
        topics_to_cover = [
            "authorization",
            "authentication",
            "IDOR",
            "field-level",
            "rate limit",
        ]
        
        all_content = " ".join([entry["user"] + entry["assistant"] for entry in self.kb_data])
        
        for topic in topics_to_cover:
            self.assertIn(topic.lower(), all_content.lower(), 
                         f"KB should cover {topic}")
    
    def test_remediation_guidance(self):
        """Test that KB includes remediation guidance."""
        remediation_found = False
        for entry in self.kb_data:
            if "remediation" in entry["user"].lower() or "fix" in entry["user"].lower():
                remediation_found = True
                # Check that response includes practical steps
                self.assertIn("Phase", entry["assistant"], 
                            "Remediation should include phased approach")
                break
        self.assertTrue(remediation_found, "KB should include remediation guidance")


class TestGraphQLSecurityTester(unittest.TestCase):
    """Test cases for GraphQL security testing script."""
    
    def test_tester_import(self):
        """Test that the security tester module can be imported."""
        try:
            from collectors.graphql_security_tester import GraphQLSecurityTester
            self.assertIsNotNone(GraphQLSecurityTester)
        except ImportError as e:
            self.fail(f"Failed to import GraphQLSecurityTester: {e}")
    
    def test_tester_instantiation(self):
        """Test that GraphQLSecurityTester can be instantiated."""
        from collectors.graphql_security_tester import GraphQLSecurityTester
        
        tester = GraphQLSecurityTester(
            url="https://api.example.com/graphql",
            token="test-token",
            verbose=False
        )
        
        self.assertEqual(tester.url, "https://api.example.com/graphql")
        self.assertEqual(tester.token, "test-token")
        self.assertFalse(tester.verbose)
        self.assertEqual(len(tester.findings), 0)
    
    def test_tester_methods_exist(self):
        """Test that all required testing methods exist."""
        from collectors.graphql_security_tester import GraphQLSecurityTester
        
        tester = GraphQLSecurityTester("https://example.com/graphql")
        
        methods = [
            'test_introspection',
            'test_idor',
            'test_idor_batch',
            'test_jwt_algorithm_confusion',
            'test_mutation_authorization',
            'test_field_level_authorization',
            'test_rate_limiting',
            'generate_report',
            'run_all_tests',
        ]
        
        for method in methods:
            self.assertTrue(hasattr(tester, method), 
                          f"Tester should have {method} method")
            self.assertTrue(callable(getattr(tester, method)), 
                          f"{method} should be callable")


if __name__ == '__main__':
    unittest.main()
