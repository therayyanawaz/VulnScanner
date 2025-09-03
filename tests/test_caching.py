"""
Tests for caching functionality.

Test scenarios:
1. OSV cache storage and retrieval
2. Cache TTL expiration handling
3. JSON serialization/deserialization
4. Cache key collision handling
5. Cache invalidation scenarios
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from vulnscanner.caching import cache_osv_result, get_cached_osv, json_dumps, json_loads


class TestJsonSerialization:
    """Test JSON serialization utilities."""

    def test_json_dumps_basic(self):
        """
        Test Case: Basic JSON serialization
        Expected: Should serialize data consistently
        """
        data = {"key": "value", "number": 42, "list": [1, 2, 3]}
        result = json_dumps(data)

        # Should be valid JSON string
        assert isinstance(result, str)
        # Should be compact (no extra whitespace)
        assert " " not in result.replace('"', "").replace(":", "").replace(",", "")

    def test_json_dumps_sorted(self):
        """
        Test Case: JSON serialization with sorted keys
        Expected: Should produce consistent output regardless of input order
        """
        data1 = {"b": 2, "a": 1, "c": 3}
        data2 = {"a": 1, "b": 2, "c": 3}

        result1 = json_dumps(data1)
        result2 = json_dumps(data2)

        # Should be identical despite different input order
        assert result1 == result2

    def test_json_loads_basic(self):
        """
        Test Case: Basic JSON deserialization
        Expected: Should deserialize JSON strings correctly
        """
        json_str = '{"key": "value", "number": 42}'
        result = json_loads(json_str)

        assert result == {"key": "value", "number": 42}

    def test_json_roundtrip(self):
        """
        Test Case: JSON serialization roundtrip
        Expected: Should preserve data through serialize/deserialize cycle
        """
        original_data = {
            "string": "test",
            "number": 42,
            "float": 3.14,
            "boolean": True,
            "null": None,
            "list": [1, 2, 3],
            "nested": {"inner": "value"},
        }

        serialized = json_dumps(original_data)
        deserialized = json_loads(serialized)

        assert deserialized == original_data


class TestOsvCaching:
    """Test OSV caching functionality."""

    def test_cache_osv_result_basic(self, temp_db, sample_osv_data):
        """
        Test Case: Basic OSV result caching
        Expected: Should store OSV data with correct parameters
        """
        cache_osv_result("npm", "test-package", "1.0.0", sample_osv_data)

        # Verify data was stored
        import sqlite3

        with sqlite3.connect(temp_db) as conn:
            row = conn.execute(
                """
                SELECT ecosystem, package, version, json FROM osv_cache 
                WHERE ecosystem = ? AND package = ? AND version = ?
                """,
                ("npm", "test-package", "1.0.0"),
            ).fetchone()

            assert row is not None
            assert row[0] == "npm"
            assert row[1] == "test-package"
            assert row[2] == "1.0.0"

            # Verify JSON data
            cached_data = json_loads(row[3])
            assert cached_data == sample_osv_data

    def test_cache_osv_result_update(self, temp_db, sample_osv_data):
        """
        Test Case: OSV cache entry update
        Expected: Should update existing entries with new data
        """
        # Cache initial data
        cache_osv_result("npm", "test-package", "1.0.0", sample_osv_data)

        # Cache updated data for same package
        updated_data = {"vulns": [], "updated": True}
        cache_osv_result("npm", "test-package", "1.0.0", updated_data)

        # Verify only one entry exists with updated data
        import sqlite3

        with sqlite3.connect(temp_db) as conn:
            rows = conn.execute(
                """
                SELECT json FROM osv_cache 
                WHERE ecosystem = ? AND package = ? AND version = ?
                """,
                ("npm", "test-package", "1.0.0"),
            ).fetchall()

            assert len(rows) == 1
            cached_data = json_loads(rows[0][0])
            assert cached_data == updated_data

    def test_get_cached_osv_fresh(self, temp_db, sample_osv_data):
        """
        Test Case: Retrieve fresh cached OSV data
        Expected: Should return cached data when within TTL
        """
        cache_osv_result("npm", "test-package", "1.0.0", sample_osv_data)

        # Should return cached data immediately
        result = get_cached_osv("npm", "test-package", "1.0.0")
        assert result == sample_osv_data

    def test_get_cached_osv_expired(self, temp_db, sample_osv_data, test_settings):
        """
        Test Case: Retrieve expired cached OSV data
        Expected: Should return None when cache has expired
        """
        # Use very short TTL for testing
        test_settings.osv_ttl_hours = 0  # Immediate expiration

        with patch("vulnscanner.caching.settings", test_settings):
            cache_osv_result("npm", "test-package", "1.0.0", sample_osv_data)

            # Should return None due to immediate expiration
            result = get_cached_osv("npm", "test-package", "1.0.0")
            assert result is None

    def test_get_cached_osv_not_found(self, temp_db):
        """
        Test Case: Retrieve non-existent cached OSV data
        Expected: Should return None when no cache entry exists
        """
        result = get_cached_osv("npm", "nonexistent-package", "1.0.0")
        assert result is None

    def test_cache_different_ecosystems(self, temp_db, sample_osv_data):
        """
        Test Case: Cache entries for different ecosystems
        Expected: Should handle multiple ecosystems independently
        """
        # Cache for different ecosystems
        cache_osv_result("npm", "test-package", "1.0.0", sample_osv_data)
        cache_osv_result("pypi", "test-package", "1.0.0", sample_osv_data)
        cache_osv_result("go", "test-package", "v1.0.0", sample_osv_data)

        # Verify all entries exist
        npm_result = get_cached_osv("npm", "test-package", "1.0.0")
        pypi_result = get_cached_osv("pypi", "test-package", "1.0.0")
        go_result = get_cached_osv("go", "test-package", "v1.0.0")

        assert npm_result == sample_osv_data
        assert pypi_result == sample_osv_data
        assert go_result == sample_osv_data

        # Verify they are independent
        assert get_cached_osv("npm", "test-package", "v1.0.0") is None
        assert get_cached_osv("go", "test-package", "1.0.0") is None

    def test_cache_version_specificity(self, temp_db, sample_osv_data):
        """
        Test Case: Cache version specificity
        Expected: Should handle different versions of same package independently
        """
        # Cache different versions
        cache_osv_result("npm", "test-package", "1.0.0", sample_osv_data)
        cache_osv_result("npm", "test-package", "1.0.1", {"different": "data"})
        cache_osv_result("npm", "test-package", "2.0.0", {"major": "version"})

        # Verify each version is cached independently
        v100 = get_cached_osv("npm", "test-package", "1.0.0")
        v101 = get_cached_osv("npm", "test-package", "1.0.1")
        v200 = get_cached_osv("npm", "test-package", "2.0.0")

        assert v100 == sample_osv_data
        assert v101 == {"different": "data"}
        assert v200 == {"major": "version"}

        # Verify non-existent version returns None
        assert get_cached_osv("npm", "test-package", "3.0.0") is None

    def test_cache_ttl_calculation(self, temp_db, sample_osv_data, test_settings):
        """
        Test Case: Cache TTL calculation accuracy
        Expected: Should respect configured TTL precisely
        """
        # Set 1-hour TTL
        test_settings.osv_ttl_hours = 1

        with patch("vulnscanner.caching.settings", test_settings):
            # Mock current time to test TTL logic
            fixed_time = datetime(2024, 8, 1, 12, 0, 0, tzinfo=timezone.utc)

            with patch("vulnscanner.caching.datetime") as mock_datetime:
                mock_datetime.now.return_value = fixed_time
                mock_datetime.fromisoformat = datetime.fromisoformat

                cache_osv_result("npm", "test-package", "1.0.0", sample_osv_data)

                # Should be found immediately
                result = get_cached_osv("npm", "test-package", "1.0.0")
                assert result == sample_osv_data

                # Move time forward by 30 minutes (within TTL)
                mock_datetime.now.return_value = fixed_time + timedelta(minutes=30)
                result = get_cached_osv("npm", "test-package", "1.0.0")
                assert result == sample_osv_data

                # Move time forward by 2 hours (beyond TTL)
                mock_datetime.now.return_value = fixed_time + timedelta(hours=2)
                result = get_cached_osv("npm", "test-package", "1.0.0")
                assert result is None
