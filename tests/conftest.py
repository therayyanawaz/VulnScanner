"""
Pytest configuration and shared fixtures for VulnScanner tests.
"""

import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

import pytest

from vulnscanner.config import Settings
from vulnscanner.db import ensure_database


@pytest.fixture
def temp_db() -> Generator[str, None, None]:
    """Create a temporary database for testing with proper isolation."""
    # Use unique filename per test to avoid conflicts
    import uuid

    unique_suffix = str(uuid.uuid4())[:8]

    with tempfile.NamedTemporaryFile(suffix=f"-{unique_suffix}.db", delete=False) as f:
        db_path = f.name

    # Set environment variable for tests with isolation
    original_db = os.environ.get("VULNSCANNER_DB")
    os.environ["VULNSCANNER_DB"] = db_path

    try:
        # Ensure clean database state
        if Path(db_path).exists():
            Path(db_path).unlink()
        ensure_database()
        yield db_path
    finally:
        # Force close any open connections
        try:
            import sqlite3

            # Close any potential connections by connecting and closing
            conn = sqlite3.connect(db_path)
            conn.close()
        except:
            pass

        # Restore environment
        if original_db:
            os.environ["VULNSCANNER_DB"] = original_db
        else:
            os.environ.pop("VULNSCANNER_DB", None)

        # Cleanup with retries for Windows
        for attempt in range(3):
            try:
                Path(db_path).unlink(missing_ok=True)
                break
            except (OSError, PermissionError):
                import time

                time.sleep(0.1)  # Brief delay before retry


@pytest.fixture
def test_settings(temp_db) -> Settings:
    """Create test settings with safe defaults using isolated temp database."""
    # Ensure database is initialized for the temp_db
    from vulnscanner.db import ensure_database

    original_env = os.environ.get("VULNSCANNER_DB")
    os.environ["VULNSCANNER_DB"] = temp_db
    try:
        ensure_database()
    finally:
        if original_env:
            os.environ["VULNSCANNER_DB"] = original_env
        else:
            os.environ.pop("VULNSCANNER_DB", None)

    return Settings(
        database_path=temp_db,  # Use the isolated temp database
        nvd_api_key=None,
        user_agent="VulnScanner-Test/0.0.1",
        nvd_max_per_30s=50,  # Conservative for tests
        nvd_max_days_per_request=1,  # Small windows for tests
        osv_ttl_hours=1,
        kev_ttl_hours=1,
        epss_ttl_hours=1,
    )


@pytest.fixture
def isolated_test_settings() -> Settings:
    """Create test settings with in-memory database for isolated tests."""
    settings = Settings(
        database_path=":memory:",
        nvd_api_key=None,
        user_agent="VulnScanner-Test/0.0.1",
        nvd_max_per_30s=50,  # Conservative for tests
        nvd_max_days_per_request=1,  # Small windows for tests
        osv_ttl_hours=1,
        kev_ttl_hours=1,
        epss_ttl_hours=1,
    )
    ensure_database()
    return settings


@pytest.fixture
def sample_cve_data():
    """Sample CVE data for testing."""
    return {
        "cve": {
            "id": "CVE-2024-TEST-001",
            "lastModified": "2024-08-01T10:30:00.000Z",
            "published": "2024-08-01T08:00:00.000Z",
            "vulnStatus": "Analyzed",
            "descriptions": [
                {"lang": "en", "value": "Test vulnerability for unit testing purposes."}
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                        },
                    }
                ]
            },
        }
    }


@pytest.fixture
def sample_nvd_response():
    """Sample NVD API response for testing."""
    return {
        "resultsPerPage": 2000,
        "startIndex": 0,
        "totalResults": 2,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2024-08-01T12:00:00.000Z",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-TEST-001",
                    "lastModified": "2024-08-01T10:30:00.000Z",
                    "published": "2024-08-01T08:00:00.000Z",
                    "vulnStatus": "Analyzed",
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-TEST-002",
                    "lastModified": "2024-08-01T11:15:00.000Z",
                    "published": "2024-08-01T09:00:00.000Z",
                    "vulnStatus": "Analyzed",
                }
            },
        ],
    }


@pytest.fixture
def sample_osv_data():
    """Sample OSV API response for testing."""
    return {
        "vulns": [
            {
                "id": "OSV-2024-TEST-001",
                "published": "2024-08-01T08:00:00Z",
                "modified": "2024-08-01T10:30:00Z",
                "aliases": ["CVE-2024-TEST-001"],
                "summary": "Test vulnerability in test-package",
                "details": "This is a test vulnerability for unit testing.",
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "test-package"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.3"}],
                            }
                        ],
                    }
                ],
                "severity": [
                    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
                ],
            }
        ]
    }
