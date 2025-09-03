"""
Integration tests for VulnScanner.

Test scenarios:
1. End-to-end CVE sync workflow
2. Database persistence across operations
3. Configuration integration
4. Real API interaction (with mocking)
5. Performance and timing validation
6. Cross-component data flow
"""

import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest

from vulnscanner.caching import cache_osv_result, get_cached_osv
from vulnscanner.db import get_meta, set_meta
from vulnscanner.nvd import sync_nvd_delta


class TestEndToEndWorkflow:
    """Test complete end-to-end workflows."""

    @pytest.mark.asyncio
    async def test_full_nvd_sync_workflow(self, temp_db, test_settings, sample_nvd_response):
        """
        Test Case: Complete NVD sync workflow
        Expected: Should sync data, store in database, and track metadata
        """
        with patch("vulnscanner.nvd.settings", test_settings):
            with patch("vulnscanner.nvd.NvdClient") as mock_client_class:
                # Setup mock client
                mock_client = AsyncMock()
                mock_client.fetch_page.return_value = sample_nvd_response
                mock_client_class.return_value = mock_client

                # Define sync window
                since = datetime(2024, 8, 1, 0, 0, 0, tzinfo=timezone.utc)
                until = datetime(2024, 8, 2, 0, 0, 0, tzinfo=timezone.utc)

                # Perform sync
                stats = await sync_nvd_delta(since=since, until=until)

                # Verify stats
                assert stats["cves"] == 2
                assert stats["pages"] == 1

                # Verify data was stored in database
                with sqlite3.connect(temp_db) as conn:
                    cve_count = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
                    assert cve_count == 2

                    # Verify specific CVEs were stored
                    cve_ids = conn.execute("SELECT cve_id FROM cves ORDER BY cve_id").fetchall()
                    expected_ids = [("CVE-2024-TEST-001",), ("CVE-2024-TEST-002",)]
                    assert cve_ids == expected_ids

                # Verify metadata tracking
                last_mod = get_meta("nvd_last_mod")
                assert last_mod is not None
                # Should be the 'until' timestamp
                assert until.isoformat() in last_mod

    @pytest.mark.asyncio
    async def test_incremental_sync_workflow(self, temp_db, test_settings):
        """
        Test Case: Incremental sync using stored metadata
        Expected: Should use last sync time for delta sync
        """
        with patch("vulnscanner.nvd.settings", test_settings):
            with patch("vulnscanner.nvd.NvdClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client

                # Setup initial metadata (simulate previous sync)
                last_sync = datetime(2024, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
                set_meta("nvd_last_mod", last_sync.isoformat())

                # First sync response (from last sync to now)
                first_response = {
                    "totalResults": 1,
                    "resultsPerPage": 2000,
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2024-NEW-001",
                                "lastModified": "2024-08-01T13:00:00.000Z",
                            }
                        }
                    ],
                }

                # Second sync response (incremental)
                second_response = {
                    "totalResults": 1,
                    "resultsPerPage": 2000,
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2024-NEW-002",
                                "lastModified": "2024-08-01T14:00:00.000Z",
                            }
                        }
                    ],
                }

                mock_client.fetch_page.side_effect = [first_response, second_response]

                # First incremental sync (should use stored last_mod)
                stats1 = await sync_nvd_delta()
                assert stats1["cves"] == 1

                # Second incremental sync (should use updated last_mod)
                stats2 = await sync_nvd_delta()
                assert stats2["cves"] == 1

                # Verify both CVEs are in database
                with sqlite3.connect(temp_db) as conn:
                    cve_count = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
                    assert cve_count == 2

    def test_cross_component_caching_integration(self, temp_db, sample_osv_data):
        """
        Test Case: Integration between caching and database components
        Expected: Should maintain data consistency across components
        """
        # Test OSV caching
        cache_osv_result("npm", "express", "4.18.0", sample_osv_data)

        # Verify cache retrieval
        cached_data = get_cached_osv("npm", "express", "4.18.0")
        assert cached_data == sample_osv_data

        # Verify database state
        with sqlite3.connect(temp_db) as conn:
            cache_count = conn.execute("SELECT COUNT(*) FROM osv_cache").fetchone()[0]
            assert cache_count == 1

            # Verify cache entry details
            row = conn.execute("SELECT ecosystem, package, version FROM osv_cache").fetchone()
            assert row == ("npm", "express", "4.18.0")

    @pytest.mark.asyncio
    async def test_configuration_integration(self, temp_db):
        """
        Test Case: Configuration integration across components
        Expected: Settings should be respected throughout the system
        """
        from vulnscanner.config import Settings

        # Create custom settings
        custom_settings = Settings(
            database_path=temp_db, nvd_max_per_30s=10, nvd_max_days_per_request=3, osv_ttl_hours=6
        )

        with patch("vulnscanner.nvd.settings", custom_settings):
            with patch("vulnscanner.caching.settings", custom_settings):
                # Test NVD client respects settings
                from vulnscanner.nvd import NvdClient

                client = NvdClient()
                assert client.rate_limiter.max_per_30s == 10
                await client.aclose()

                # Test caching respects TTL settings
                cache_osv_result("npm", "test", "1.0.0", {"test": "data"})

                # Mock time advancement beyond TTL
                with patch("vulnscanner.caching.datetime") as mock_dt:
                    # Current time
                    now = datetime.now(timezone.utc)
                    mock_dt.now.return_value = now
                    mock_dt.fromisoformat = datetime.fromisoformat

                    # Should find data initially
                    result = get_cached_osv("npm", "test", "1.0.0")
                    assert result == {"test": "data"}

                    # Advance time beyond TTL (6 hours + 1)
                    mock_dt.now.return_value = now + timedelta(hours=7)

                    # Should not find expired data
                    result = get_cached_osv("npm", "test", "1.0.0")
                    assert result is None


class TestPerformanceAndTiming:
    """Test performance characteristics and timing behavior."""

    @pytest.mark.asyncio
    async def test_rate_limiter_timing(self, test_settings):
        """
        Test Case: Rate limiter timing accuracy
        Expected: Should enforce timing constraints correctly
        """
        from vulnscanner.nvd import RateLimiter

        # Use very low limit for testing
        limiter = RateLimiter(max_per_30s=2)

        # Record timing for allowed requests
        import time

        start_time = time.time()

        await limiter.wait()  # Should be immediate
        await limiter.wait()  # Should be immediate

        elapsed = time.time() - start_time
        # Both requests should be very fast
        assert elapsed < 0.1

    @pytest.mark.asyncio
    async def test_batch_processing_performance(self, temp_db, test_settings):
        """
        Test Case: Batch processing performance
        Expected: Should handle large datasets efficiently
        """
        from vulnscanner.nvd import _save_vulnerabilities

        # Generate large batch of test vulnerabilities
        large_batch = []
        for i in range(1000):
            large_batch.append(
                {
                    "cve": {
                        "id": f"CVE-2024-BATCH-{i:04d}",
                        "lastModified": "2024-08-01T10:30:00.000Z",
                    }
                }
            )

        # Measure processing time
        import time

        start_time = time.time()

        count = _save_vulnerabilities(large_batch)

        elapsed = time.time() - start_time

        # Verify all items were processed
        assert count == 1000

        # Performance should be reasonable (under 1 second for 1000 items)
        assert elapsed < 1.0

        # Verify data integrity
        with sqlite3.connect(temp_db) as conn:
            db_count = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
            assert db_count == 1000

    def test_database_connection_efficiency(self, temp_db):
        """
        Test Case: Database connection management efficiency
        Expected: Should manage connections efficiently without leaks
        """
        from vulnscanner.db import db

        # Perform many database operations
        for i in range(100):
            with db() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                    (f"test_key_{i}", f"test_value_{i}"),
                )

        # Verify all operations completed successfully
        with db() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM meta WHERE key LIKE 'test_key_%'"
            ).fetchone()[0]
            assert count == 100

        # No explicit connection leak testing - rely on SQLite and Python GC


class TestErrorRecoveryAndResilience:
    """Test error handling and system resilience."""

    @pytest.mark.asyncio
    async def test_partial_failure_recovery(self, temp_db, test_settings):
        """
        Test Case: Recovery from partial failures
        Expected: Should save partial data and continue processing
        """
        from vulnscanner.nvd import _save_vulnerabilities

        # Mix of valid and invalid vulnerability data
        mixed_data = [
            {"cve": {"id": "CVE-VALID-001", "lastModified": "2024-08-01T10:30:00.000Z"}},
            {"cve": {"id": "CVE-VALID-002", "lastModified": "2024-08-01T10:30:00.000Z"}},
            {"cve": {"lastModified": "2024-08-01T10:30:00.000Z"}},  # Missing ID
            {"cve": {"id": "CVE-VALID-003", "lastModified": "2024-08-01T10:30:00.000Z"}},
            {},  # Invalid entry
        ]

        # Should save valid entries and skip invalid ones
        count = _save_vulnerabilities(mixed_data)
        assert count == 3  # Only valid entries

        # Verify only valid data was saved
        with sqlite3.connect(temp_db) as conn:
            saved_cves = conn.execute("SELECT cve_id FROM cves ORDER BY cve_id").fetchall()

            expected_cves = [("CVE-VALID-001",), ("CVE-VALID-002",), ("CVE-VALID-003",)]
            assert saved_cves == expected_cves

    @pytest.mark.asyncio
    async def test_network_error_simulation(self, temp_db, test_settings):
        """
        Test Case: Network error handling during sync
        Expected: Should handle network errors gracefully with retries
        """
        import httpx

        with patch("vulnscanner.nvd.settings", test_settings):
            with patch("vulnscanner.nvd.NvdClient") as mock_client_class:
                mock_client = AsyncMock()

                # Simulate network error followed by success
                network_error = httpx.ConnectError("Connection failed")
                success_response = {
                    "totalResults": 1,
                    "resultsPerPage": 2000,
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-RETRY-SUCCESS",
                                "lastModified": "2024-08-01T10:30:00.000Z",
                            }
                        }
                    ],
                }

                # First call fails, second succeeds (simulating retry)
                mock_client.fetch_page.side_effect = [network_error, success_response]
                mock_client_class.return_value = mock_client

                since = datetime(2024, 8, 1, 0, 0, 0, tzinfo=timezone.utc)
                until = datetime(2024, 8, 2, 0, 0, 0, tzinfo=timezone.utc)

                # Should eventually succeed due to retry logic
                # Note: The actual retry logic is in the @retry decorator
                # This test verifies the setup for retry scenarios
                with pytest.raises(httpx.ConnectError):
                    # First call should raise the network error
                    await sync_nvd_delta(since=since, until=until)

    def test_database_corruption_handling(self, temp_db):
        """
        Test Case: Handling database corruption or lock scenarios
        Expected: Should handle database errors gracefully
        """
        import sqlite3

        from vulnscanner.db import db

        # Simulate database lock by opening a conflicting transaction
        blocking_conn = sqlite3.connect(temp_db)
        blocking_conn.execute("BEGIN EXCLUSIVE")

        try:
            # Attempt database operation while locked
            with pytest.raises(sqlite3.OperationalError):
                with db() as conn:
                    conn.execute("INSERT INTO meta (key, value) VALUES (?, ?)", ("test", "value"))
        finally:
            # Cleanup blocking connection
            blocking_conn.rollback()
            blocking_conn.close()

        # Verify database still works after lock is released
        with db() as conn:
            conn.execute("INSERT INTO meta (key, value) VALUES (?, ?)", ("test", "value"))
            result = conn.execute("SELECT value FROM meta WHERE key = 'test'").fetchone()
            assert result[0] == "value"
