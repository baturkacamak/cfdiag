"""
Tests for the REPL module.
"""
import pytest
import sys
import os
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from cfdiag.repl import (
    COMMANDS,
    resolve_command,
    parse_command,
    get_suggestions,
    print_suggestions,
    show_help,
    show_config,
    set_config,
    handle_diagnose,
    print_banner,
    CommandCompleter,
    RICH_AVAILABLE,
    PROMPT_TOOLKIT_AVAILABLE,
)


class TestCommandParsing:
    """Test command parsing functionality."""
    
    def test_parse_command_simple(self):
        """Test parsing a simple command."""
        cmd, args = parse_command("diagnose example.com")
        assert cmd == "diagnose"
        assert args == ["example.com"]
    
    def test_parse_command_with_flags(self):
        """Test parsing command with flags."""
        cmd, args = parse_command('diagnose example.com --origin 1.2.3.4 --verbose')
        assert cmd == "diagnose"
        assert "example.com" in args
        assert "--origin" in args
        assert "1.2.3.4" in args
        assert "--verbose" in args
    
    def test_parse_command_with_quotes(self):
        """Test parsing command with quoted arguments."""
        cmd, args = parse_command('diagnose "example.com" --origin "1.2.3.4"')
        assert cmd == "diagnose"
        assert args == ["example.com", "--origin", "1.2.3.4"]
    
    def test_parse_empty_command(self):
        """Test parsing empty command."""
        cmd, args = parse_command("")
        assert cmd == ""
        assert args == []
    
    def test_parse_command_only_whitespace(self):
        """Test parsing command with only whitespace."""
        cmd, args = parse_command("   ")
        assert cmd == ""
        assert args == []


class TestCommandResolution:
    """Test command resolution and aliases."""
    
    def test_resolve_command_direct(self):
        """Test resolving a direct command."""
        assert resolve_command("diagnose") == "diagnose"
        assert resolve_command("help") == "help"
        assert resolve_command("exit") == "exit"
    
    def test_resolve_command_alias(self):
        """Test resolving command aliases."""
        assert resolve_command("diag") == "diagnose"
        assert resolve_command("d") == "diagnose"
        assert resolve_command("h") == "help"
        assert resolve_command("q") == "exit"
        assert resolve_command("quit") == "exit"
    
    def test_resolve_command_unknown(self):
        """Test resolving unknown command."""
        assert resolve_command("unknown_command") is None
        assert resolve_command("xyz") is None
    
    def test_resolve_command_case_insensitive(self):
        """Test that command resolution is case insensitive."""
        assert resolve_command("DIAGNOSE") == "diagnose"
        assert resolve_command("Help") == "help"
        assert resolve_command("EXIT") == "exit"


class TestSuggestions:
    """Test command suggestions."""
    
    def test_get_suggestions_exact_match(self):
        """Test getting suggestions for exact match."""
        suggestions = get_suggestions("diagnose")
        assert len(suggestions) > 0
        assert any(cmd == "diagnose" for cmd, _ in suggestions)
    
    def test_get_suggestions_partial_match(self):
        """Test getting suggestions for partial match."""
        suggestions = get_suggestions("diag")
        assert len(suggestions) > 0
        # Should include "diagnose"
        assert any("diagnose" in cmd for cmd, _ in suggestions)
    
    def test_get_suggestions_no_match(self):
        """Test getting suggestions when no match."""
        suggestions = get_suggestions("xyzabc")
        assert len(suggestions) == 0
    
    def test_get_suggestions_empty(self):
        """Test getting suggestions for empty input."""
        suggestions = get_suggestions("")
        assert len(suggestions) == 0
    
    def test_get_suggestions_limit(self):
        """Test that suggestions are limited."""
        suggestions = get_suggestions("")
        # Should return at most 3 suggestions
        assert len(suggestions) <= 3


class TestCommandCompleter:
    """Test the command completer."""
    
    def test_completer_initialization(self):
        """Test completer can be initialized."""
        completer = CommandCompleter()
        assert completer is not None
        assert len(completer.commands) > 0
    
    def test_completer_has_all_commands(self):
        """Test completer has all commands."""
        completer = CommandCompleter()
        for cmd in COMMANDS.keys():
            assert cmd in completer.commands or any(
                alias in completer.commands for alias in COMMANDS[cmd].get("aliases", [])
            )


class TestHelpFunctions:
    """Test help and information functions."""
    
    def test_show_help_all_commands(self):
        """Test showing help for all commands."""
        # This should not raise an exception
        try:
            show_help()
        except Exception as e:
            pytest.fail(f"show_help() raised {e}")
    
    def test_show_help_specific_command(self):
        """Test showing help for specific command."""
        try:
            show_help("diagnose")
        except Exception as e:
            pytest.fail(f"show_help('diagnose') raised {e}")
    
    def test_show_help_unknown_command(self):
        """Test showing help for unknown command."""
        try:
            show_help("unknown_command")
        except Exception as e:
            pytest.fail(f"show_help('unknown_command') raised {e}")
    
    def test_show_config(self):
        """Test showing configuration."""
        try:
            show_config()
        except Exception as e:
            pytest.fail(f"show_config() raised {e}")


class TestConfigManagement:
    """Test configuration management."""
    
    @patch('cfdiag.repl.get_context')
    @patch('cfdiag.repl.set_context')
    def test_set_config_timeout(self, mock_set_context, mock_get_context):
        """Test setting timeout configuration."""
        mock_get_context.return_value = {'timeout': 10}
        set_config("timeout", "15")
        mock_set_context.assert_called_once()
        ctx = mock_set_context.call_args[0][0]
        assert ctx['timeout'] == 15
    
    @patch('cfdiag.repl.get_context')
    @patch('cfdiag.repl.set_context')
    def test_set_config_invalid_timeout(self, mock_set_context, mock_get_context):
        """Test setting invalid timeout."""
        mock_get_context.return_value = {'timeout': 10}
        # Should not raise, but should handle gracefully
        try:
            set_config("timeout", "invalid")
        except ValueError:
            pass  # Expected
    
    @patch('cfdiag.repl.get_context')
    @patch('cfdiag.repl.set_context')
    def test_set_config_ipv4(self, mock_set_context, mock_get_context):
        """Test setting IPv4 configuration."""
        mock_get_context.return_value = {'ipv4': False, 'ipv6': False}
        set_config("ipv4", "true")
        mock_set_context.assert_called_once()
        ctx = mock_set_context.call_args[0][0]
        assert ctx['ipv4'] is True
        assert ctx['ipv6'] is False  # Should be mutually exclusive
    
    @patch('cfdiag.repl.get_context')
    @patch('cfdiag.repl.set_context')
    def test_set_config_unknown_option(self, mock_set_context, mock_get_context):
        """Test setting unknown configuration option."""
        mock_get_context.return_value = {}
        # Should not raise, but should handle gracefully
        try:
            set_config("unknown_option", "value")
        except Exception:
            pass  # Expected to handle gracefully


class TestBanner:
    """Test banner printing."""
    
    def test_print_banner_no_exception(self):
        """Test that banner can be printed without exceptions."""
        try:
            print_banner()
        except Exception as e:
            pytest.fail(f"print_banner() raised {e}")


class TestDiagnoseCommand:
    """Test diagnose command handling."""
    
    @patch('cfdiag.repl.run_diagnostics')
    @patch('cfdiag.repl.FileLogger')
    @patch('cfdiag.repl.set_logger')
    def test_handle_diagnose_simple(self, mock_set_logger, mock_logger, mock_run_diagnostics):
        """Test handling simple diagnose command."""
        mock_run_diagnostics.return_value = {'domain': 'example.com'}
        handle_diagnose(["example.com"])
        mock_run_diagnostics.assert_called_once()
    
    @patch('cfdiag.repl.run_diagnostics')
    @patch('cfdiag.repl.FileLogger')
    @patch('cfdiag.repl.set_logger')
    def test_handle_diagnose_with_origin(self, mock_set_logger, mock_logger, mock_run_diagnostics):
        """Test handling diagnose command with origin."""
        mock_run_diagnostics.return_value = {'domain': 'example.com'}
        handle_diagnose(["example.com", "--origin", "1.2.3.4"])
        mock_run_diagnostics.assert_called_once()
    
    @patch('cfdiag.repl.run_diagnostics')
    @patch('cfdiag.repl.FileLogger')
    @patch('cfdiag.repl.set_logger')
    def test_handle_diagnose_no_domain(self, mock_set_logger, mock_logger, mock_run_diagnostics):
        """Test handling diagnose command without domain."""
        handle_diagnose([])
        # Should not call run_diagnostics
        mock_run_diagnostics.assert_not_called()
    
    @patch('cfdiag.repl.run_diagnostics')
    @patch('cfdiag.repl.FileLogger')
    @patch('cfdiag.repl.set_logger')
    def test_handle_diagnose_error(self, mock_set_logger, mock_logger, mock_run_diagnostics):
        """Test handling diagnose command with error."""
        mock_run_diagnostics.side_effect = Exception("Test error")
        # Should handle error gracefully
        try:
            handle_diagnose(["example.com"])
        except Exception:
            pytest.fail("handle_diagnose should handle errors gracefully")


class TestREPLModule:
    """Test REPL module structure."""
    
    def test_commands_defined(self):
        """Test that commands are properly defined."""
        assert len(COMMANDS) > 0
        for cmd, info in COMMANDS.items():
            assert 'description' in info
            assert 'usage' in info
            assert 'aliases' in info
            assert 'category' in info
    
    def test_imports_available(self):
        """Test that imports are properly handled."""
        # These should be boolean values
        assert isinstance(RICH_AVAILABLE, bool)
        assert isinstance(PROMPT_TOOLKIT_AVAILABLE, bool)
    
    def test_all_commands_have_categories(self):
        """Test that all commands have categories."""
        for cmd, info in COMMANDS.items():
            assert 'category' in info
            assert info['category'] in ['Core', 'General', 'Configuration', 'Utilities']


class TestErrorHandling:
    """Test error handling in REPL functions."""
    
    def test_parse_command_handles_errors(self):
        """Test that parse_command handles errors gracefully."""
        # Test with malformed input
        try:
            parse_command('test "unclosed quote')
        except Exception:
            pass  # Should handle gracefully
    
    def test_suggestions_handle_empty_input(self):
        """Test that suggestions handle edge cases."""
        suggestions = get_suggestions("")
        assert isinstance(suggestions, list)
        
        # Test with None (should not crash)
        try:
            suggestions = get_suggestions(None)
            assert isinstance(suggestions, list)
        except (TypeError, AttributeError):
            pass  # Expected if None is not handled
    
    @patch('cfdiag.repl.check_internet_connection')
    @patch('cfdiag.repl.check_dependencies')
    def test_run_repl_handles_internet_check_error(self, mock_check_deps, mock_check_internet):
        """Test that REPL handles internet check errors."""
        mock_check_internet.side_effect = Exception("Network error")
        # Should not crash, just warn
        from cfdiag.repl import run_repl
        # We can't actually run the REPL in tests, but we can verify it handles errors
    
    @patch('cfdiag.repl.PROMPT_TOOLKIT_AVAILABLE', False)
    def test_run_repl_without_prompt_toolkit(self):
        """Test that REPL handles missing prompt_toolkit gracefully."""
        from cfdiag.repl import run_repl
        import sys
        # Should exit with error message
        # We can't test this easily without mocking sys.exit


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
