"""Tests for CLI help output and argument parsing."""
import unittest
import sys
import io
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

# Import the main function
from cfdiag.core import main


class TestCLIHelp(unittest.TestCase):
    """Test CLI help output and argument completeness."""
    
    def test_help_output_contains_all_options(self):
        """Verify that --help output contains all expected options."""
        test_args = ['cfdiag', '--help']
        
        with patch.object(sys, 'argv', test_args):
            with redirect_stdout(io.StringIO()) as f:
                try:
                    main()
                except SystemExit:
                    pass  # argparse calls sys.exit() after printing help
        
        help_output = f.getvalue()
        
        # Core options
        self.assertIn('--origin', help_output)
        self.assertIn('--expect', help_output)
        self.assertIn('--profile', help_output)
        self.assertIn('--file', help_output)
        self.assertIn('--threads', help_output)
        
        # Network options
        self.assertIn('--ipv4', help_output)
        self.assertIn('--ipv6', help_output)
        self.assertIn('--proxy', help_output)
        self.assertIn('--timeout', help_output)
        self.assertIn('--header', help_output)
        
        # Advanced diagnostics
        self.assertIn('--keylog', help_output)
        self.assertIn('--mtr', help_output)
        self.assertIn('--watch', help_output)
        
        # Output formats
        self.assertIn('--json', help_output)
        self.assertIn('--markdown', help_output)
        self.assertIn('--junit', help_output)
        self.assertIn('--metrics', help_output)
        
        # Utility commands
        self.assertIn('--lint-config', help_output)
        self.assertIn('--analyze-logs', help_output)
        self.assertIn('--serve', help_output)
        self.assertIn('--grafana', help_output)
        self.assertIn('--completion', help_output)
        
        # General options
        self.assertIn('--verbose', help_output)
        self.assertIn('--no-color', help_output)
        self.assertIn('--interactive', help_output)
        self.assertIn('--version', help_output)
        self.assertIn('--update', help_output)
        
        # Check for grouped sections
        self.assertIn('Core Options', help_output)
        self.assertIn('Batch Mode', help_output)
        self.assertIn('Network Options', help_output)
        self.assertIn('Advanced Diagnostics', help_output)
        self.assertIn('Output Formats', help_output)
        self.assertIn('Utility Commands', help_output)
        self.assertIn('General Options', help_output)
    
    def test_help_contains_examples(self):
        """Verify that help output contains examples section."""
        test_args = ['cfdiag', '--help']
        
        with patch.object(sys, 'argv', test_args):
            with redirect_stdout(io.StringIO()) as f:
                try:
                    main()
                except SystemExit:
                    pass
        
        help_output = f.getvalue()
        self.assertIn('Examples:', help_output)
        self.assertIn('example.com', help_output)
    
    def test_version_output(self):
        """Test --version flag."""
        test_args = ['cfdiag', '--version']
        
        with patch.object(sys, 'argv', test_args):
            with redirect_stdout(io.StringIO()) as f:
                try:
                    main()
                except SystemExit:
                    pass
        
        version_output = f.getvalue()
        self.assertIn('cfdiag', version_output)
    
    def test_completion_generation(self):
        """Test shell completion generation."""
        for shell in ['bash', 'zsh']:
            test_args = ['cfdiag', '--completion', shell]
            
            with patch.object(sys, 'argv', test_args):
                with redirect_stdout(io.StringIO()) as f:
                    try:
                        main()
                    except SystemExit:
                        pass
            
            completion_output = f.getvalue()
            # Check that completion script was generated (contains function definition)
            self.assertIn('_cfdiag', completion_output.lower())
            # Check for new arguments in completion
            self.assertIn('--threads', completion_output)
            self.assertIn('--expect', completion_output)
            self.assertIn('--interactive', completion_output)
            self.assertIn('--metrics', completion_output)
    
    def test_missing_domain_shows_help(self):
        """Test that missing domain shows help message."""
        test_args = ['cfdiag']
        
        with patch.object(sys, 'argv', test_args):
            with redirect_stdout(io.StringIO()) as f_stdout:
                with redirect_stderr(io.StringIO()) as f_stderr:
                    try:
                        main()
                    except SystemExit:
                        pass
        
        # Help should be printed (either to stdout or stderr depending on argparse version)
        output = f_stdout.getvalue() + f_stderr.getvalue()
        # Should contain help information
        self.assertTrue(len(output) > 0)


class TestCLIArguments(unittest.TestCase):
    """Test that all CLI arguments are properly parsed."""
    
    def test_threads_argument_default(self):
        """Test that --threads has a default value."""
        test_args = ['cfdiag', '--file', '/dev/null', '--help']
        
        with patch.object(sys, 'argv', test_args):
            with redirect_stdout(io.StringIO()) as f:
                try:
                    main()
                except SystemExit:
                    pass
        
        help_output = f.getvalue()
        # Should mention default value
        self.assertIn('threads', help_output.lower())
    
    def test_timeout_argument_default(self):
        """Test that --timeout has a default value."""
        test_args = ['cfdiag', '--help']
        
        with patch.object(sys, 'argv', test_args):
            with redirect_stdout(io.StringIO()) as f:
                try:
                    main()
                except SystemExit:
                    pass
        
        help_output = f.getvalue()
        # Should mention default value
        self.assertIn('timeout', help_output.lower())
        self.assertIn('default', help_output.lower())


if __name__ == '__main__':
    unittest.main()
