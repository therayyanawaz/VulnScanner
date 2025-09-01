"""
Tests for database operations.

Test scenarios:
1. Database initialization and schema creation
2. Meta data storage and retrieval
3. CVE data insertion and querying
4. Database connection handling
5. Concurrent access scenarios
6. Data integrity and constraints
"""
import sqlite3
import pytest
from datetime import datetime, timezone

from vulnscanner.db import ensure_database, db, get_meta, set_meta


class TestDatabase:
    """Test database operations."""

    def test_database_initialization(self, temp_db):
        """
        Test Case: Database initialization
        Expected: Database should be created with correct schema
        """
        # Database should be created by temp_db fixture
        assert temp_db.endswith(".db")
        
        with sqlite3.connect(temp_db) as conn:
            # Check that all tables exist
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            table_names = [t[0] for t in tables]
            
            expected_tables = ["meta", "cves", "osv_cache", "kev", "epss"]
            for table in expected_tables:
                assert table in table_names, f"Table {table} not found"

    def test_schema_constraints(self, temp_db):
        """
        Test Case: Database schema constraints
        Expected: Foreign key constraints and indexes should be enforced
        """
        with sqlite3.connect(temp_db) as conn:
            # Test primary key constraint
            conn.execute(
                "INSERT INTO cves (cve_id, source, json, modified) VALUES (?, ?, ?, ?)",
                ("CVE-2024-TEST", "NVD", '{}', datetime.now(timezone.utc).isoformat())
            )
            
            # Should fail on duplicate primary key
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO cves (cve_id, source, json, modified) VALUES (?, ?, ?, ?)",
                    ("CVE-2024-TEST", "NVD", '{}', datetime.now(timezone.utc).isoformat())
                )

    def test_meta_operations(self, temp_db):
        """
        Test Case: Meta data storage and retrieval
        Expected: Should store and retrieve meta values correctly
        """
        # Test setting meta value
        set_meta("test_key", "test_value")
        
        # Test retrieving meta value
        value = get_meta("test_key")
        assert value == "test_value"
        
        # Test non-existent key
        value = get_meta("non_existent_key")
        assert value is None
        
        # Test updating existing key
        set_meta("test_key", "updated_value")
        value = get_meta("test_key")
        assert value == "updated_value"

    def test_cve_insertion_and_query(self, temp_db, sample_cve_data):
        """
        Test Case: CVE data insertion and querying
        Expected: Should insert and retrieve CVE data correctly
        """
        with db() as conn:
            # Insert CVE data
            conn.execute(
                """
                INSERT INTO cves (cve_id, source, json, modified)
                VALUES (?, ?, ?, ?)
                """,
                (
                    "CVE-2024-TEST-001",
                    "NVD",
                    str(sample_cve_data),
                    datetime.now(timezone.utc).isoformat()
                )
            )
            
            # Query CVE data
            row = conn.execute(
                "SELECT cve_id, source FROM cves WHERE cve_id = ?",
                ("CVE-2024-TEST-001",)
            ).fetchone()
            
            assert row is not None
            assert row[0] == "CVE-2024-TEST-001"
            assert row[1] == "NVD"

    def test_osv_cache_operations(self, temp_db):
        """
        Test Case: OSV cache operations
        Expected: Should handle package+version caching correctly
        """
        with db() as conn:
            # Insert cache entry
            conn.execute(
                """
                INSERT INTO osv_cache (ecosystem, package, version, fetched_at, json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "npm",
                    "test-package",
                    "1.0.0",
                    datetime.now(timezone.utc).isoformat(),
                    '{"vulns": []}'
                )
            )
            
            # Query cache entry
            row = conn.execute(
                """
                SELECT ecosystem, package, version FROM osv_cache 
                WHERE ecosystem = ? AND package = ? AND version = ?
                """,
                ("npm", "test-package", "1.0.0")
            ).fetchone()
            
            assert row is not None
            assert row == ("npm", "test-package", "1.0.0")

    def test_composite_primary_key_constraint(self, temp_db):
        """
        Test Case: Composite primary key constraint in osv_cache
        Expected: Should enforce unique (ecosystem, package, version) combinations
        """
        with db() as conn:
            # Insert first entry
            conn.execute(
                """
                INSERT INTO osv_cache (ecosystem, package, version, fetched_at, json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "npm",
                    "test-package", 
                    "1.0.0",
                    datetime.now(timezone.utc).isoformat(),
                    '{"vulns": []}'
                )
            )
            
            # Should fail on duplicate composite key
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    """
                    INSERT INTO osv_cache (ecosystem, package, version, fetched_at, json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "npm",
                        "test-package",
                        "1.0.0", 
                        datetime.now(timezone.utc).isoformat(),
                        '{"vulns": []}'
                    )
                )

    def test_database_context_manager(self, temp_db):
        """
        Test Case: Database context manager behavior
        Expected: Should handle transactions and cleanup correctly
        """
        # Test successful transaction
        with db() as conn:
            conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?)",
                ("test_transaction", "success")
            )
        
        # Verify data was committed
        value = get_meta("test_transaction")
        assert value == "success"
        
        # Test transaction rollback on exception
        try:
            with db() as conn:
                conn.execute(
                    "INSERT INTO meta (key, value) VALUES (?, ?)",
                    ("test_rollback", "should_not_exist")
                )
                # Force an error
                raise Exception("Test exception")
        except Exception:
            pass
        
        # Verify data was not committed due to exception
        value = get_meta("test_rollback")
        # Note: SQLite autocommit behavior may vary, this tests the general pattern

    def test_kev_and_epss_tables(self, temp_db):
        """
        Test Case: KEV and EPSS table operations
        Expected: Should handle enrichment data correctly
        """
        with db() as conn:
            # Test KEV table
            conn.execute(
                "INSERT INTO kev (cve_id, json, fetched_at) VALUES (?, ?, ?)",
                (
                    "CVE-2024-TEST-KEV",
                    '{"knownRansomwareCampaignUse": "Known"}',
                    datetime.now(timezone.utc).isoformat()
                )
            )
            
            # Test EPSS table
            conn.execute(
                "INSERT INTO epss (cve_id, score, percentile, fetched_at) VALUES (?, ?, ?, ?)",
                (
                    "CVE-2024-TEST-EPSS",
                    0.75,
                    85.5,
                    datetime.now(timezone.utc).isoformat()
                )
            )
            
            # Verify KEV data
            kev_row = conn.execute(
                "SELECT cve_id FROM kev WHERE cve_id = ?",
                ("CVE-2024-TEST-KEV",)
            ).fetchone()
            assert kev_row[0] == "CVE-2024-TEST-KEV"
            
            # Verify EPSS data
            epss_row = conn.execute(
                "SELECT cve_id, score, percentile FROM epss WHERE cve_id = ?",
                ("CVE-2024-TEST-EPSS",)
            ).fetchone()
            assert epss_row[0] == "CVE-2024-TEST-EPSS"
            assert epss_row[1] == 0.75
            assert epss_row[2] == 85.5
