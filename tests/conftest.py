"""
Pytest configuration and shared fixtures for VulnScanner tests.
"""
import os
import tempfile
from pathlib import Path
from typing import Generator
import pytest
import sqlite3
from datetime import datetime, timezone

from vulnscanner.config import Settings
from vulnscanner.db import ensure_database


@pytest.fixture
def temp_db() -> Generator[str, None, None]:
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    
    # Set environment variable for tests
    original_db = os.environ.get("VULNSCANNER_DB")
    os.environ["VULNSCANNER_DB"] = db_path
    
    try:
        ensure_database()
        yield db_path
    finally:
        # Cleanup
        if original_db:
            os.environ["VULNSCANNER_DB"] = original_db
        else:
            os.environ.pop("VULNSCANNER_DB", None)
        Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def test_settings() -> Settings:
    """Create test settings with safe defaults."""
    return Settings(
        database_path=":memory:",
        nvd_api_key=None,
        user_agent="VulnScanner-Test/0.0.1",
        nvd_max_per_30s=5,  # Conservative for tests
        nvd_max_days_per_request=1,  # Small windows for tests
        osv_ttl_hours=1,
        kev_ttl_hours=1,
        epss_ttl_hours=1,
    )


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
                {
                    "lang": "en",
                    "value": "Test vulnerability for unit testing purposes."
                }
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
                            "baseSeverity": "CRITICAL"
                        }
                    }
                ]
            }
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
                    "vulnStatus": "Analyzed"
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-TEST-002", 
                    "lastModified": "2024-08-01T11:15:00.000Z",
                    "published": "2024-08-01T09:00:00.000Z",
                    "vulnStatus": "Analyzed"
                }
            }
        ]
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
                        "package": {
                            "ecosystem": "npm",
                            "name": "test-package"
                        },
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [
                                    {"introduced": "1.0.0"},
                                    {"fixed": "1.2.3"}
                                ]
                            }
                        ]
                    }
                ],
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    }
                ]
            }
        ]
    }
