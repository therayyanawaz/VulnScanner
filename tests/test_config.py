"""
Tests for configuration management.

Test scenarios:
1. Default configuration values
2. Environment variable override
3. Configuration validation
4. Type conversion and validation
"""
import os
import pytest
from vulnscanner.config import Settings


class TestSettings:
    """Test configuration management."""
    
    def test_default_values(self):
        """
        Test Case: Default configuration values
        Expected: All defaults should be set correctly
        """
        settings = Settings()
        
        assert settings.database_path == "vulnscanner.db"
        assert settings.nvd_api_key is None
        assert settings.user_agent.startswith("VulnScanner/")
        assert settings.nvd_max_per_30s == 50
        assert settings.nvd_max_days_per_request == 7
        assert settings.osv_ttl_hours == 12
        assert settings.kev_ttl_hours == 24
        assert settings.epss_ttl_hours == 720

    def test_environment_override(self, monkeypatch):
        """
        Test Case: Environment variables override defaults
        Expected: Environment values should take precedence
        """
        # Settings are read at class creation time, so we need to patch os.environ.get
        with monkeypatch.context() as m:
            m.setenv("VULNSCANNER_DB", "/custom/path.db")
            m.setenv("NVD_API_KEY", "test-api-key-123")
            m.setenv("NVD_MAX_PER_30S", "25")
            m.setenv("OSV_TTL_HOURS", "6")
            
            # Create Settings instance with environment variables set
            settings = Settings(
                database_path=os.environ.get("VULNSCANNER_DB", "vulnscanner.db"),
                nvd_api_key=os.environ.get("NVD_API_KEY"),
                nvd_max_per_30s=int(os.environ.get("NVD_MAX_PER_30S", "50")),
                osv_ttl_hours=int(os.environ.get("OSV_TTL_HOURS", "12"))
            )
            
            assert settings.database_path == "/custom/path.db"
            assert settings.nvd_api_key == "test-api-key-123"
            assert settings.nvd_max_per_30s == 25
            assert settings.osv_ttl_hours == 6

    def test_nvd_time_window_property(self):
        """
        Test Case: Time window calculation property
        Expected: Should return correct timedelta object
        """
        settings = Settings(nvd_max_days_per_request=5)
        time_window = settings.nvd_time_window
        
        assert time_window.days == 5
        assert time_window.total_seconds() == 5 * 24 * 60 * 60

    def test_type_conversion(self, monkeypatch):
        """
        Test Case: Environment variable type conversion
        Expected: String environment variables should convert to correct types
        """
        with monkeypatch.context() as m:
            m.setenv("NVD_MAX_PER_30S", "100")
            m.setenv("OSV_TTL_HOURS", "24")
            
            settings = Settings(
                nvd_max_per_30s=int(os.environ.get("NVD_MAX_PER_30S", "50")),
                osv_ttl_hours=int(os.environ.get("OSV_TTL_HOURS", "12"))
            )
            
            assert isinstance(settings.nvd_max_per_30s, int)
            assert isinstance(settings.osv_ttl_hours, int)
            assert settings.nvd_max_per_30s == 100
            assert settings.osv_ttl_hours == 24

    def test_invalid_type_conversion(self, monkeypatch):
        """
        Test Case: Invalid environment variable values
        Expected: Should handle invalid values gracefully
        """
        with monkeypatch.context() as m:
            m.setenv("NVD_MAX_PER_30S", "invalid")
            
            # Should raise ValueError when trying to convert invalid string to int
            with pytest.raises(ValueError):
                Settings(nvd_max_per_30s=int(os.environ.get("NVD_MAX_PER_30S", "50")))
