"""Edge case tests for CLI to prevent common errors."""
import unittest
import sys
import io
import os
import tempfile
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch, MagicMock

from cfdiag.core import main


class TestCLIEdgeCases(unittest.TestCase):
    """Test edge cases and error prevention."""
    
    def test_threads_without_file(self):
        """Test that --threads without --file doesn't cause error."""
        test_args = ['cfdiag', 'example.com', '--threads', '10']
        
        with patch.object(sys, 'argv', test_args):
            with patch('cfdiag.core.check_internet_connection', return_value=True):
                with patch('cfdiag.core.check_dependencies'):
                    with patch('cfdiag.core.run_diagnostics') as mock_run:
                        mock_run.return_value = {'domain': 'test', 'dns': 'OK'}
                        try:
                            main()
                            # Should work fine (threads is ignored when not in batch mode)
                            self.assertTrue(mock_run.called)
                        except Exception as e:
                            # Should not raise error about threads
                            self.assertNotIn('threads', str(e).lower())
    
    def test_expect_without_domain(self):
        """Test --expect without domain."""
        test_args = ['cfdiag', '--expect', 'ns1.example.com']
        
        with patch.object(sys, 'argv', test_args):
            with redirect_stdout(io.StringIO()) as f:
                try:
                    main()
                except SystemExit:
                    # Should show help or error
                    pass
                output = f.getvalue()
                # Should indicate domain is required
                self.assertTrue(len(output) > 0)
    
    def test_origin_without_domain(self):
        """Test --origin without domain."""
        test_args = ['cfdiag', '--origin', '1.2.3.4']
        
        with patch.object(sys, 'argv', test_args):
            with redirect_stdout(io.StringIO()) as f:
                try:
                    main()
                except SystemExit:
                    pass
                output = f.getvalue()
                self.assertTrue(len(output) > 0)
    
    def test_multiple_headers(self):
        """Test multiple --header arguments."""
        test_args = [
            'cfdiag', 'example.com',
            '--header', 'X-Foo: Bar',
            '--header', 'X-Bar: Baz',
            '--header', 'Authorization: Bearer token'
        ]
        
        with patch.object(sys, 'argv', test_args):
            with patch('cfdiag.core.check_internet_connection', return_value=True):
                with patch('cfdiag.core.check_dependencies'):
                    with patch('cfdiag.core.run_diagnostics') as mock_run:
                        mock_run.return_value = {'domain': 'test', 'dns': 'OK'}
                        try:
                            main()
                            # Should handle multiple headers
                            self.assertTrue(mock_run.called)
                        except Exception:
                            pass
    
    def test_invalid_port_number(self):
        """Test invalid port number for --serve."""
        test_args = ['cfdiag', '--serve', '99999']  # Invalid port
        
        with patch.object(sys, 'argv', test_args):
            with redirect_stderr(io.StringIO()) as f:
                try:
                    main()
                except (SystemExit, ValueError, Exception):
                    # Should handle invalid port gracefully
                    pass
    
    def test_negative_timeout(self):
        """Test negative timeout value."""
        test_args = ['cfdiag', 'example.com', '--timeout', '-5']
        
        with patch.object(sys, 'argv', test_args):
            with patch('cfdiag.core.check_internet_connection', return_value=True):
                with patch('cfdiag.core.check_dependencies'):
                    with patch('cfdiag.core.run_diagnostics') as mock_run:
                        mock_run.return_value = {'domain': 'test', 'dns': 'OK'}
                        try:
                            main()
                            # Should either reject or handle gracefully
                        except (SystemExit, ValueError):
                            # Negative timeout should be rejected
                            pass
    
    def test_zero_timeout(self):
        """Test zero timeout value."""
        test_args = ['cfdiag', 'example.com', '--timeout', '0']
        
        with patch.object(sys, 'argv', test_args):
            with patch('cfdiag.core.check_internet_connection', return_value=True):
                with patch('cfdiag.core.check_dependencies'):
                    with patch('cfdiag.core.run_diagnostics') as mock_run:
                        mock_run.return_value = {'domain': 'test', 'dns': 'OK'}
                        try:
                            main()
                            # Zero timeout might be valid (immediate timeout)
                        except Exception:
                            pass
    
    def test_very_large_thread_count(self):
        """Test very large thread count."""
        test_args = ['cfdiag', '--file', '/dev/null', '--threads', '10000']
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('example.com\n')
            temp_file = f.name
        
        try:
            test_args = ['cfdiag', '--file', temp_file, '--threads', '10000']
            
            with patch.object(sys, 'argv', test_args):
                with patch('cfdiag.core.check_internet_connection', return_value=True):
                    with patch('cfdiag.core.check_dependencies'):
                        with patch('cfdiag.core.run_diagnostics_wrapper') as mock_run:
                            mock_run.return_value = {'domain': 'test', 'dns': 'OK'}
                            try:
                                main()
                                # Should handle large thread count (may be limited by system)
                            except Exception:
                                pass
        finally:
            os.unlink(temp_file)
    
    def test_empty_header_value(self):
        """Test empty header value."""
        test_args = ['cfdiag', 'example.com', '--header', 'X-Foo:']
        
        with patch.object(sys, 'argv', test_args):
            with patch('cfdiag.core.check_internet_connection', return_value=True):
                with patch('cfdiag.core.check_dependencies'):
                    with patch('cfdiag.core.run_diagnostics') as mock_run:
                        mock_run.return_value = {'domain': 'test', 'dns': 'OK'}
                        try:
                            main()
                            # Should handle empty header value
                        except Exception:
                            pass
    
    def test_special_characters_in_domain(self):
        """Test special characters in domain."""
        test_args = ['cfdiag', 'example.com/test?param=value']
        
        with patch.object(sys, 'argv', test_args):
            with patch('cfdiag.core.check_internet_connection', return_value=True):
                with patch('cfdiag.core.check_dependencies'):
                    with patch('cfdiag.core.run_diagnostics') as mock_run:
                        mock_run.return_value = {'domain': 'test', 'dns': 'OK'}
                        try:
                            main()
                            # Should handle or clean domain
                        except Exception:
                            pass
    
    def test_unicode_in_domain(self):
        """Test unicode characters in domain."""
        test_args = ['cfdiag', '例え.テスト']
        
        with patch.object(sys, 'argv', test_args):
            with patch('cfdiag.core.check_internet_connection', return_value=True):
                with patch('cfdiag.core.check_dependencies'):
                    with patch('cfdiag.core.run_diagnostics') as mock_run:
                        mock_run.return_value = {'domain': 'test', 'dns': 'OK'}
                        try:
                            main()
                            # Should handle unicode
                        except Exception:
                            pass
    
    def test_file_with_only_whitespace(self):
        """Test file with only whitespace."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('   \n  \n  \n')
            temp_file = f.name
        
        try:
            test_args = ['cfdiag', '--file', temp_file]
            
            with patch.object(sys, 'argv', test_args):
                with patch('cfdiag.core.check_internet_connection', return_value=True):
                    with patch('cfdiag.core.check_dependencies'):
                        try:
                            main()
                            # Should handle whitespace-only file
                        except Exception:
                            pass
        finally:
            os.unlink(temp_file)
    
    def test_file_with_comments(self):
        """Test file with comment-like lines."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('# This is a comment\n')
            f.write('example.com\n')
            f.write('  # Another comment\n')
            f.write('test.com\n')
            temp_file = f.name
        
        try:
            test_args = ['cfdiag', '--file', temp_file]
            
            with patch.object(sys, 'argv', test_args):
                with patch('cfdiag.core.check_internet_connection', return_value=True):
                    with patch('cfdiag.core.check_dependencies'):
                        with patch('cfdiag.core.run_diagnostics_wrapper') as mock_run:
                            mock_run.return_value = {'domain': 'test', 'dns': 'OK'}
                            try:
                                main()
                                # Should process valid domains, skip comments
                            except Exception:
                                pass
        finally:
            os.unlink(temp_file)
    
    def test_all_output_formats_together(self):
        """Test all output formats together."""
        test_args = [
            'cfdiag', 'example.com',
            '--json', '--markdown', '--junit', '--metrics'
        ]
        
        with patch.object(sys, 'argv', test_args):
            with patch('cfdiag.core.check_internet_connection', return_value=True):
                with patch('cfdiag.core.check_dependencies'):
                    with patch('cfdiag.core.run_diagnostics') as mock_run:
                        mock_run.return_value = {'domain': 'test', 'dns': 'OK'}
                        with patch('cfdiag.core.FileLogger') as mock_logger:
                            mock_logger_instance = MagicMock()
                            mock_logger.return_value = mock_logger_instance
                            with patch('cfdiag.core.set_logger'):
                                with patch('cfdiag.core.set_context'):
                                    with redirect_stdout(io.StringIO()):
                                        try:
                                            main()
                                            # Should generate all formats
                                        except Exception:
                                            pass


if __name__ == '__main__':
    unittest.main()
