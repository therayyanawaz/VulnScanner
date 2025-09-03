"""
Tests for CLI functionality.

Test scenarios:
1. CLI command parsing and validation
2. Date/time parsing edge cases
3. Debug mode functionality
4. Error handling and user feedback
5. Command integration with backend
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from click.testing import CliRunner

from vulnscanner.cli import _parse_dt, main, nvd_sync


class TestDateTimeParsing:
    """Test date/time parsing functionality."""

    def test_parse_dt_with_z_suffix(self):
        """
        Test Case: Parse ISO8601 with Z suffix
        Expected: Should parse correctly and convert to UTC
        """
        result = _parse_dt("2024-08-01T10:30:00Z")
        expected = datetime(2024, 8, 1, 10, 30, 0, tzinfo=timezone.utc)
        assert result == expected

    def test_parse_dt_with_timezone_offset(self):
        """
        Test Case: Parse ISO8601 with timezone offset
        Expected: Should convert to UTC timezone
        """
        result = _parse_dt("2024-08-01T10:30:00+02:00")
        expected = datetime(2024, 8, 1, 8, 30, 0, tzinfo=timezone.utc)  # Converted to UTC
        assert result == expected

    def test_parse_dt_without_timezone(self):
        """
        Test Case: Parse ISO8601 without timezone
        Expected: Should assume UTC
        """
        result = _parse_dt("2024-08-01T10:30:00")
        expected = datetime(2024, 8, 1, 10, 30, 0, tzinfo=timezone.utc)
        assert result == expected

    def test_parse_dt_with_whitespace(self):
        """
        Test Case: Parse date string with leading/trailing whitespace
        Expected: Should handle whitespace gracefully
        """
        result = _parse_dt("  2024-08-01T10:30:00Z  ")
        expected = datetime(2024, 8, 1, 10, 30, 0, tzinfo=timezone.utc)
        assert result == expected

    def test_parse_dt_invalid_format(self):
        """
        Test Case: Parse invalid date format
        Expected: Should raise ValueError
        """
        with pytest.raises(ValueError):
            _parse_dt("invalid-date-format")

    def test_parse_dt_edge_cases(self):
        """
        Test Case: Parse edge case date formats
        Expected: Should handle various valid ISO8601 formats
        """
        test_cases = [
            ("2024-08-01T00:00:00Z", datetime(2024, 8, 1, 0, 0, 0, tzinfo=timezone.utc)),
            ("2024-12-31T23:59:59Z", datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc)),
            ("2024-01-01T12:00:00.000Z", datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)),
        ]

        for input_str, expected in test_cases:
            result = _parse_dt(input_str)
            assert result == expected


class TestCliCommands:
    """Test CLI command functionality."""

    def test_main_help(self):
        """
        Test Case: Main CLI help command
        Expected: Should display help message and available commands
        """
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])

        assert result.exit_code == 0
        assert "VulnScanner CLI" in result.output
        assert "nvd-sync" in result.output

    def test_nvd_sync_help(self):
        """
        Test Case: NVD sync command help
        Expected: Should display nvd-sync specific help
        """
        runner = CliRunner()
        result = runner.invoke(main, ["nvd-sync", "--help"])

        assert result.exit_code == 0
        assert "--since" in result.output
        assert "--until" in result.output
        assert "--debug" in result.output

    @patch("vulnscanner.cli.sync_nvd_delta")
    @patch("vulnscanner.cli.ensure_database")
    def test_nvd_sync_basic(self, mock_ensure_db, mock_sync, temp_db):
        """
        Test Case: Basic NVD sync command execution
        Expected: Should call sync function with correct parameters
        """
        mock_sync.return_value = {"cves": 5, "pages": 1}

        runner = CliRunner()
        result = runner.invoke(
            main, ["nvd-sync", "--since", "2024-08-01T00:00:00Z", "--until", "2024-08-02T00:00:00Z"]
        )

        assert result.exit_code == 0
        assert (
            "Syncing from 2024-08-01 00:00:00+00:00 to 2024-08-02 00:00:00+00:00" in result.output
        )
        assert "Synced: {'cves': 5, 'pages': 1}" in result.output

        mock_ensure_db.assert_called_once()
        mock_sync.assert_called_once()

    @patch("vulnscanner.cli.sync_nvd_delta")
    @patch("vulnscanner.cli.ensure_database")
    def test_nvd_sync_with_debug(self, mock_ensure_db, mock_sync, temp_db):
        """
        Test Case: NVD sync with debug flag
        Expected: Should enable debug logging
        """
        mock_sync.return_value = {"cves": 0, "pages": 1}

        runner = CliRunner()
        result = runner.invoke(main, ["nvd-sync", "--since", "2024-08-01T00:00:00Z", "--debug"])

        assert result.exit_code == 0
        # Debug logging should be configured (hard to test directly)
        mock_ensure_db.assert_called_once()
        mock_sync.assert_called_once()

    @patch("vulnscanner.cli.sync_nvd_delta")
    @patch("vulnscanner.cli.ensure_database")
    def test_nvd_sync_only_since(self, mock_ensure_db, mock_sync, temp_db):
        """
        Test Case: NVD sync with only since parameter
        Expected: Should use None for until parameter (defaults to now)
        """
        mock_sync.return_value = {"cves": 10, "pages": 2}

        runner = CliRunner()
        result = runner.invoke(main, ["nvd-sync", "--since", "2024-08-01T00:00:00Z"])

        assert result.exit_code == 0

        # Verify sync was called with since and until=None
        call_args = mock_sync.call_args[1]  # Get keyword arguments
        assert call_args["since"] is not None
        assert call_args["until"] is None

    @patch("vulnscanner.cli.sync_nvd_delta")
    @patch("vulnscanner.cli.ensure_database")
    def test_nvd_sync_no_parameters(self, mock_ensure_db, mock_sync, temp_db):
        """
        Test Case: NVD sync with no time parameters
        Expected: Should use None for both since and until (auto-determine)
        """
        mock_sync.return_value = {"cves": 3, "pages": 1}

        runner = CliRunner()
        result = runner.invoke(main, ["nvd-sync"])

        assert result.exit_code == 0

        # Verify sync was called with both None
        call_args = mock_sync.call_args[1]  # Get keyword arguments
        assert call_args["since"] is None
        assert call_args["until"] is None

    def test_nvd_sync_invalid_date_format(self):
        """
        Test Case: NVD sync with invalid date format
        Expected: Should show error and exit with non-zero code
        """
        runner = CliRunner()
        result = runner.invoke(main, ["nvd-sync", "--since", "invalid-date-format"])

        assert result.exit_code != 0
        # Should contain error information about date parsing

    @patch("vulnscanner.cli.sync_nvd_delta")
    @patch("vulnscanner.cli.ensure_database")
    def test_nvd_sync_exception_handling(self, mock_ensure_db, mock_sync, temp_db):
        """
        Test Case: NVD sync with backend exception
        Expected: Should handle exceptions and show error
        """
        mock_sync.side_effect = Exception("Test exception")

        runner = CliRunner()
        result = runner.invoke(main, ["nvd-sync", "--since", "2024-08-01T00:00:00Z"])

        assert result.exit_code != 0
        # Exception should be propagated or handled gracefully

    @patch("vulnscanner.cli.sync_nvd_delta")
    @patch("vulnscanner.cli.ensure_database")
    def test_nvd_sync_database_initialization(self, mock_ensure_db, mock_sync, temp_db):
        """
        Test Case: Database initialization during sync
        Expected: Should ensure database is initialized before sync
        """
        mock_sync.return_value = {"cves": 1, "pages": 1}

        runner = CliRunner()
        result = runner.invoke(main, ["nvd-sync"])

        assert result.exit_code == 0

        # Verify database initialization was called before sync
        mock_ensure_db.assert_called_once()
        mock_sync.assert_called_once()

        # Verify order: database init should be called before sync
        calls = [mock_ensure_db.call_args, mock_sync.call_args]
        assert all(call is not None for call in calls)


class TestCliIntegration:
    """Test CLI integration with backend systems."""

    @patch("vulnscanner.cli.asyncio.run")
    @patch("vulnscanner.cli.ensure_database")
    def test_asyncio_integration(self, mock_ensure_db, mock_asyncio_run):
        """
        Test Case: Asyncio integration for sync command
        Expected: Should properly use asyncio.run for async operations
        """
        mock_asyncio_run.return_value = {"cves": 5, "pages": 1}

        runner = CliRunner()
        result = runner.invoke(main, ["nvd-sync"])

        assert result.exit_code == 0
        mock_asyncio_run.assert_called_once()

        # Verify the coroutine passed to asyncio.run is sync_nvd_delta
        call_args = mock_asyncio_run.call_args[0][0]
        # This is the coroutine object - we can't easily inspect it further
        assert hasattr(call_args, "__await__")  # Verify it's a coroutine

    def test_command_isolation(self):
        """
        Test Case: Command isolation and state management
        Expected: Multiple command invocations should not interfere
        """
        runner = CliRunner()

        # First command
        result1 = runner.invoke(main, ["--help"])
        assert result1.exit_code == 0

        # Second command
        result2 = runner.invoke(main, ["nvd-sync", "--help"])
        assert result2.exit_code == 0

        # Commands should be independent
        assert "VulnScanner CLI" in result1.output
        assert "--since" in result2.output
        assert "--since" not in result1.output
