#!/usr/bin/env python3
"""
VulnScanner Test Runner and Demo Script

This script provides an easy way to run tests and demonstrate the
test suite capabilities for the VulnScanner project.
"""
import os
import sys
import subprocess
from pathlib import Path


def print_header(title: str) -> None:
    """Print a formatted header."""
    print("\n" + "=" * 60)
    print(f"🧪 {title}")
    print("=" * 60)


def run_command(cmd: list[str], description: str) -> bool:
    """Run a command and return success status."""
    print(f"\n▶️  {description}")
    print(f"   Command: {' '.join(cmd)}")
    print("-" * 50)
    
    try:
        result = subprocess.run(cmd, capture_output=False, text=True)
        success = result.returncode == 0
        if success:
            print(f"✅ {description} - PASSED")
        else:
            print(f"❌ {description} - FAILED (exit code: {result.returncode})")
        return success
    except Exception as e:
        print(f"❌ {description} - ERROR: {e}")
        return False


def main():
    """Main test runner function."""
    print_header("VulnScanner Test Suite Runner")
    
    # Check if we're in the right directory
    if not Path("src/vulnscanner").exists():
        print("❌ Error: Please run this script from the VulnScanner project root directory")
        sys.exit(1)
    
    # Ensure pytest is installed
    print("\n📦 Checking test dependencies...")
    if not run_command([sys.executable, "-m", "pytest", "--version"], "Check pytest installation"):
        print("\n💡 Installing test dependencies...")
        run_command([sys.executable, "-m", "pip", "install", "pytest", "pytest-asyncio", "pytest-cov"], 
                   "Install test dependencies")
    
    print_header("Quick Validation Tests")
    
    # Run quick validation tests
    validation_tests = [
        ([sys.executable, "-m", "pytest", "tests/test_run_all.py::test_project_structure", "-v"], 
         "Project Structure Validation"),
        ([sys.executable, "-m", "pytest", "tests/test_run_all.py::test_import_all_modules", "-v"], 
         "Module Import Validation"),
        ([sys.executable, "-m", "pytest", "tests/test_config.py::TestSettings::test_default_values", "-v"], 
         "Configuration Validation"),
    ]
    
    all_passed = True
    for cmd, desc in validation_tests:
        if not run_command(cmd, desc):
            all_passed = False
    
    if all_passed:
        print_header("Unit Tests")
        
        # Run unit tests by category
        unit_test_categories = [
            (["tests/test_config.py"], "Configuration Tests"),
            (["tests/test_database.py"], "Database Tests"),  
            (["tests/test_caching.py"], "Caching Tests"),
            (["tests/test_cli.py"], "CLI Tests"),
        ]
        
        for test_files, desc in unit_test_categories:
            cmd = [sys.executable, "-m", "pytest"] + test_files + ["-v", "--tb=short"]
            run_command(cmd, desc)
        
        print_header("Integration Tests")
        
        # Run integration tests (these might take longer)
        integration_cmd = [sys.executable, "-m", "pytest", "tests/test_integration.py", "-v", "--tb=short"]
        run_command(integration_cmd, "Integration Tests")
        
        print_header("Test Coverage Report")
        
        # Run with coverage if available
        coverage_cmd = [
            sys.executable, "-m", "pytest", 
            "--cov=vulnscanner", 
            "--cov-report=term-missing",
            "--cov-report=html",
            "tests/",
            "-v"
        ]
        if run_command(coverage_cmd, "Full Test Suite with Coverage"):
            print("\n📊 Coverage report generated in htmlcov/index.html")
    
    print_header("Test Suite Summary")
    
    if all_passed:
        print("🎉 All validation tests passed!")
        print("\n📋 Available Test Commands:")
        print("   pytest                              # Run all tests")
        print("   pytest tests/test_config.py         # Run config tests")
        print("   pytest -m unit                      # Run unit tests only")
        print("   pytest -m integration               # Run integration tests only")
        print("   pytest --cov=vulnscanner            # Run with coverage")
        print("   pytest -v --tb=short                # Verbose with short traceback")
        print("   python tests/test_run_all.py        # Run validation script")
        
        print("\n🧪 Test Categories:")
        print("   • Configuration: Environment variables, settings")
        print("   • Database: SQLite operations, schema validation")
        print("   • NVD API: Rate limiting, data sync, error handling")
        print("   • Caching: OSV cache, TTL, serialization")
        print("   • CLI: Command parsing, error handling")
        print("   • Integration: End-to-end workflows")
        
        print("\n🎯 Test Coverage Areas:")
        print("   ✅ Unit Tests: 50+ test scenarios")
        print("   ✅ Integration Tests: End-to-end workflows")
        print("   ✅ Error Handling: Edge cases and failures")
        print("   ✅ Performance: Rate limiting and timing")
        print("   ✅ Configuration: Environment and settings")
        print("   ✅ Database: Schema and data integrity")
        
    else:
        print("⚠️  Some validation tests failed. Please check the output above.")
        print("   Run individual test files to diagnose specific issues.")
    
    print("\n📚 For more information, see:")
    print("   • README.md - Project documentation")
    print("   • tests/ directory - Complete test suite")
    print("   • pytest.ini - Test configuration")


if __name__ == "__main__":
    main()
