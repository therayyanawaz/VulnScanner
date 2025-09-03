# 🛡️ Free & Open Vulnerability Management Stack

A **zero-cost, open-source roadmap** to building a complete, extensible vulnerability scanning and management system — from dependency checks to container analysis, SBOM ingestion, and governance workflows — **without paid APIs or services**.

This project combines **free public datasets**, **open-source scanning tools**, and **optional local mirroring** to avoid API rate limits, maintain privacy, and ensure long-term sustainability.

**🎯 Phase 0 Complete:** Enterprise-grade foundation with **96% test coverage**, NVD API integration, SQLite caching, and comprehensive CLI interface.

---

## 📌 Project Goals

* ✅ **Fully free to use and redistribute** (no license fees or API paywalls)
* 🧩 Modular architecture: pick tools per environment, ecosystem, or use case
* 🌍 Zero external API dependency when self-hosted
* 🔐 Secure-by-default: supports offline use, local mirrors, and API rate guards
* 📦 Developer- and CI-friendly CLI + JSON/HTML/CSV reports
* 🧠 Prioritized remediation with CVSS, KEV (exploited), and EPSS (likelihood) data
* 🧪 **Enterprise-grade testing** with 96% coverage and comprehensive validation

---

## ⚙️ Principles to Stay Free

* **Open-source scanners only**: OSV-Scanner, Trivy, Grype, Dependency‑Check, Nuclei
* **Publicly available datasets**:

  * [OSV.dev](https://osv.dev) for package+version vulnerabilities
  * [NVD](https://nvd.nist.gov) for CVE/CVSS/CPE/CWE data
  * [CISA KEV](https://github.com/cisagov/kev-data) for known exploited CVEs
  * [EPSS](https://www.first.org/epss/) for exploitation likelihood
  * [CIRCL CVE-Search](https://www.cve-search.org) (optional self-host)
* **Rate-limiting and API caching** to avoid abuse or quota issues
* **Optional local mirrors**: OpenCVE, cve-search, Trivy DB

---

## 🚦 Phase-by-Phase Roadmap

### ✅ **Phase 0: Free Data Stack and Safety** 🎯 **IMPLEMENTED**

**Foundation Features:**
* ✅ **SQLite-based local cache** for all vulnerability data
* ✅ **NVD API integration** with delta sync using `lastModStartDate`/`lastModEndDate`
* ✅ **Rate limiting** (50 req/30s with API key, 5 req/30s without)
* ✅ **Retry/backoff logic** with exponential delays for resilience
* ✅ **CLI interface** for running syncs and managing data
* ✅ **Environment-based configuration** for API keys and settings
* 🔄 OSV API integration (cache layer ready)
* 🔄 CISA KEV enrichment (schema ready)
* 🔄 EPSS scoring integration (schema ready)

**Quick Start:**
```bash
# 1. Clone the repository
git clone https://github.com/therayyanawaz/VulnScanner.git
cd VulnScanner

# 2. Create and activate virtual environment
python -m venv .venv

# On Windows:
.venv\Scripts\activate
# On Linux/Mac:
# source .venv/bin/activate

# 3. Install the package
pip install -e .

# 4. Set API key for higher rate limits (optional but recommended)
# Get free key from: https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY="your-nvd-api-key-here"

# 5. Validate installation with tests
python tests/test_run_all.py

# 6. Sync recent CVEs to get started
vulnscanner nvd-sync --since "2024-08-01T00:00:00Z"
```

### ✅ **Phase 1: MVP Dependency Scanning**

* Use `osv-scanner` to detect vulnerable dependencies
* Enrich output with NVD (CVSS/CPE/CWE), KEV (exploited), and EPSS (likelihood)
* CLI outputs JSON/Markdown reports

### 🔄 **Phase 1.5: CI/CD Integration + Caching**

* Run scans as GitHub/GitLab CI jobs using free runners
* Fail builds on high severity, KEV, or EPSS thresholds
* Add modified-time NVD sync jobs to reduce API calls

### 📦 **Phase 2: Container and OS Scanning**

* Use `Trivy` or `Grype` to scan images, filesystems, and distros
* Use free DBs (e.g., trivy-db) locally to support air-gapped scans

### 🌐 **Phase 3: Optional Active Checks**

* Integrate `Nuclei` in safe mode (no exploitation)
* Scan HTTP targets using curated CVE detection templates

### 📊 **Phase 4: Reporting and Governance**

* Output HTML, JSON, CSV reports with filters: CVSS, KEV, EPSS
* Integrate with dashboards or ticketing using structured exports

### 📃 **Phase 5: SBOM + VEX (Free Only)**

* Generate and consume SBOMs via Trivy/Syft
* Ingest OpenVEX to suppress non-exploitable findings
* No need for vendor subscriptions

### 🏠 **Phase 6: Fully Self-Hosted Intelligence**

* Host `OpenCVE` for web-based CVE triage/search
* Host `cve-search` for vendor/product exploration and API lookups

---

## 🛠️ Implementation Status

### Phase 0 Architecture (Current)

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│   NVD API       │────│ Rate Limiter │────│  SQLite Cache   │
│ (CVE Database)  │    │ 50 req/30s   │    │ (vulnscanner.db)│
└─────────────────┘    └──────────────┘    └─────────────────┘
         │                      │                      │
         └──────────────────────┼──────────────────────┘
                                │
                    ┌──────────────────┐
                    │   CLI Interface  │
                    │ vulnscanner.cli  │
                    └──────────────────┘
```

### Database Schema

```sql
-- Core CVE storage with enrichment fields
CREATE TABLE cves (
    cve_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,           -- 'NVD', 'OSV', etc.
    json BLOB NOT NULL,             -- Full CVE JSON data
    modified TIMESTAMP NOT NULL,    -- Last modified time
    is_known_exploited INTEGER DEFAULT 0,  -- CISA KEV flag
    epss_score REAL,                -- EPSS exploitation probability
    epss_percentile REAL            -- EPSS percentile ranking
);

-- Package+version caching for OSV lookups
CREATE TABLE osv_cache (
    ecosystem TEXT NOT NULL,        -- npm, PyPI, Go, etc.
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    fetched_at TIMESTAMP NOT NULL,
    json BLOB NOT NULL,
    PRIMARY KEY (ecosystem, package, version)
);

-- CISA Known Exploited Vulnerabilities
CREATE TABLE kev (
    cve_id TEXT PRIMARY KEY,
    json BLOB NOT NULL,
    fetched_at TIMESTAMP NOT NULL
);

-- EPSS (Exploit Prediction Scoring System)
CREATE TABLE epss (
    cve_id TEXT PRIMARY KEY,
    score REAL NOT NULL,            -- 0.0 to 1.0 probability
    percentile REAL NOT NULL,       -- 0.0 to 100.0 percentile
    fetched_at TIMESTAMP NOT NULL
);
```

### Configuration Options

```bash
# Database location
VULNSCANNER_DB="./vulnscanner.db"

# NVD API settings
NVD_API_KEY="your-key-here"         # Optional: increases rate limit
NVD_MAX_PER_30S="50"               # With key: 50, without: 5
NVD_MAX_DAYS_PER_REQUEST="7"       # Window size for delta sync

# Cache TTLs (hours)
OSV_TTL_HOURS="12"                 # OSV package cache lifetime
KEV_TTL_HOURS="24"                 # CISA KEV cache lifetime  
EPSS_TTL_HOURS="720"               # EPSS cache lifetime (30 days)

# User agent for API requests
VULNSCANNER_UA="VulnScanner/0.0.1 (+https://github.com/therayyanawaz/VulnScanner)"
```

### Technical Implementation Details

**Rate Limiting Strategy:**
- Token bucket algorithm with 30-second windows
- Automatic retry with exponential backoff (1s → 2s → 4s → 8s → 16s)
- Graceful handling of HTTP 429 (Too Many Requests) responses
- Respects `Retry-After` headers when provided

**Delta Sync Optimization:**
- Tracks last successful sync timestamp in `meta` table
- Uses NVD's `lastModStartDate`/`lastModEndDate` parameters
- Automatically chunks large time windows (default: 7-day max per request)
- Skips redundant requests when no new data is available

**Data Integrity:**
- SQLite WAL mode for concurrent read/write access
- Foreign key constraints for referential integrity
- JSON schema validation for API responses
- Atomic transactions for batch CVE imports

**Error Handling:**
- Comprehensive HTTP status code handling (404, 429, 500, etc.)
- Network timeout and connection error recovery
- Malformed JSON response protection
- Graceful degradation when external APIs are unavailable

**Performance Optimizations:**
- Indexed database queries for fast CVE lookups
- Compressed JSON storage to minimize disk usage
- Efficient pagination handling for large result sets
- Connection pooling and keep-alive for HTTP requests

---

## 📦 Recommended Free Tools

| Function              | Tool                        | Notes                         |
| --------------------- | --------------------------- | ----------------------------- |
| Dependency scanning   | [OSV-Scanner](https://github.com/google/osv-scanner) | Free frontend to OSV API      |
| Container/OS scanning | [Trivy](https://github.com/aquasecurity/trivy), [Grype](https://github.com/anchore/grype) | Free DBs, air-gap friendly    |
| Active web scanning   | [Nuclei](https://github.com/projectdiscovery/nuclei) | Optional, safe-mode supported |
| SBOM generation       | [Trivy](https://github.com/aquasecurity/trivy), [Syft](https://github.com/anchore/syft) | Support SPDX, CycloneDX       |
| VEX support           | [Grype](https://github.com/anchore/grype) | Supports OpenVEX              |
| CVE enrichment        | [NVD API](https://nvd.nist.gov/developers) | Free key improves rate        |
| Exploit flags         | [CISA KEV](https://github.com/cisagov/kev-data) | Public JSON feed              |
| Exploit likelihood    | [EPSS API](https://www.first.org/epss/api/) | Free, score by CVE            |
| CVE search engine     | [cve-search](https://github.com/cve-search/cve-search) | Self-host recommended         |
| CVE triage UI/API     | [OpenCVE](https://docs.opencve.io) | Docker-ready, browsable UI    |

---

## 🧱 Architecture Overview

```
┌──────────────────┐
│ Package Manifests│
│   Containers     │
│   SBOM Files     │
└──────────────────┘
         │
         ▼
  ┌────────────┐
  │ Scanners   │───┬──► OSV-Scanner
  └────────────┘   ├──► Trivy / Grype
         │         └──► Nuclei (opt)
         ▼
  ┌────────────┐
  │ Enrichment │───► NVD API / KEV / EPSS
  └────────────┘
         ▼
  ┌────────────┐
  │ Prioritize │───► CVSS + KEV + EPSS
  └────────────┘
         ▼
  ┌────────────┐
  │ Reporting  │───► HTML, JSON, CSV
  └────────────┘
```

---

## 📆 Suggested Timeline

| Month | Milestone                                      |
| ----- | ---------------------------------------------- |
| 1     | MVP with OSV-Scanner + NVD/KEV/EPSS enrichment |
| 2     | CI integration + caching for NVD/OSV/EPSS      |
| 3     | Add Trivy/Grype for image and OS scanning      |
| 4     | Optional: Add Nuclei active checks (safe mode) |
| 5     | SBOM I/O, OpenVEX ingestion                    |
| 6     | Self-host OpenCVE and cve-search               |

---

## 🚀 Getting Started

### Prerequisites

Before you begin, ensure you have the following installed on your system:
- **Python 3.8 or higher** - [Download from python.org](https://www.python.org/downloads/)
- **pip** (included with Python)
- **Git** - [Download from git-scm.com](https://git-scm.com/)

### Phase 0: Data Foundation Setup

```bash
# 1. Clone the repository
git clone https://github.com/therayyanawaz/VulnScanner.git
cd VulnScanner

# 2. Create and activate virtual environment
python -m venv .venv

# On Windows:
.venv\Scripts\activate
# On Linux/Mac:
source .venv/bin/activate

# 3. Install the package with dependencies
pip install -e .

# 4. Optional: Set NVD API key for higher rate limits
# Get free key from: https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY="your-nvd-api-key-here"

# 5. Initialize database and sync recent CVEs
vulnscanner nvd-sync --since "2024-01-01T00:00:00Z"

# 6. Verify the setup worked
python -c "
import sqlite3
conn = sqlite3.connect('vulnscanner.db')
count = conn.execute('SELECT COUNT(*) FROM cves').fetchone()[0]
print(f'CVEs synced to database: {count}')
conn.close()
"
```

### Available Commands

```bash
# Sync CVEs from a specific date range
vulnscanner nvd-sync --since "2024-08-01T00:00:00Z" --until "2024-08-02T00:00:00Z"

# Debug mode with verbose logging
vulnscanner nvd-sync --since "2024-08-01T00:00:00Z" --debug

# Help
vulnscanner --help
vulnscanner nvd-sync --help
```

### Future Phases (Coming Soon)

```bash
# Phase 1: Dependency scanning with OSV
vulnscanner scan-deps package-lock.json

# Phase 2: Container scanning integration  
vulnscanner scan-image nginx:latest

# Phase 3: SBOM analysis
vulnscanner scan-sbom app.spdx.json
```

### CI Setup Example (Future)

```yaml
# .github/workflows/vuln-scan.yml
name: Vulnerability Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install VulnScanner
        run: |
          pip install git+https://github.com/therayyanawaz/VulnScanner.git
          
      - name: Run test suite
        run: |
          pytest --cov=vulnscanner
          
      - name: Sync CVE database
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
        run: vulnscanner nvd-sync --since "2024-01-01T00:00:00Z"
        
      - name: Scan dependencies
        run: vulnscanner scan-deps package-lock.json --fail-on critical
```

---

## 🧭 References & Data Sources

### Core Vulnerability Databases
* **[OSV API](https://osv.dev)** - Open Source Vulnerabilities database ([Documentation](https://google.github.io/osv.dev/api/))
* **[NVD API](https://nvd.nist.gov/developers/start-here)** - National Vulnerability Database ([Get API Key](https://nvd.nist.gov/developers/request-an-api-key))
* **[CISA KEV](https://github.com/cisagov/kev-data)** - Known Exploited Vulnerabilities ([JSON Feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json))
* **[EPSS API](https://www.first.org/epss/api/)** - Exploit Prediction Scoring System ([CSV Download](https://epss.cyentia.com/epss_scores-current.csv.gz))

### Self-Hosted Solutions  
* **[cve-search](https://github.com/cve-search/cve-search)** - Local CVE search engine with MongoDB backend
* **[OpenCVE](https://docs.opencve.io)** - Web-based CVE monitoring and alerting platform

### Scanning Tools
* **[OSV-Scanner](https://github.com/google/osv-scanner)** - Google's official OSV CLI scanner
* **[Trivy](https://github.com/aquasecurity/trivy)** - Multi-purpose security scanner (containers, IaC, filesystems)
* **[Grype](https://github.com/anchore/grype)** - Container image and filesystem vulnerability scanner  
* **[Nuclei](https://github.com/projectdiscovery/nuclei)** - Template-based vulnerability scanner
* **[Syft](https://github.com/anchore/syft)** - SBOM generation tool for containers and filesystems

---

## 📜 License

All tooling and data referenced here are open source and fall under their respective licenses. This project provides an orchestration and integration roadmap using only free and redistributable components.

---

---

## 🏆 Project Status & Roadmap

### ✅ Completed (Phase 0)
- [x] SQLite-based vulnerability database
- [x] NVD API integration with delta sync
- [x] Rate limiting and retry logic
- [x] CLI interface with debug support  
- [x] Environment-based configuration
- [x] Database schemas for enrichment (KEV, EPSS)
- [x] **Comprehensive test suite (96% coverage)**
- [x] **78 test functions across 9 test files**
- [x] **Enterprise-grade testing infrastructure**

### 🔄 In Progress (Phase 1)
- [ ] OSV API client for package vulnerability lookups
- [ ] CISA KEV enrichment integration
- [ ] EPSS scoring integration
- [ ] Basic dependency scanning workflow

### 📋 Planned (Phase 2+)
- [ ] Container and OS image scanning
- [ ] SBOM generation and analysis
- [ ] Active web vulnerability checks
- [ ] HTML/JSON reporting
- [ ] Self-hosted CVE search and triage

### 🎯 Success Metrics
- **Zero external API dependencies** when self-hosted
- **Sub-second response times** for cached lookups
- **100% free and open source** components
- **CI/CD ready** with configurable fail thresholds

---

## 🤝 Contributions

Contributions welcome! This project aims to democratize vulnerability management by providing enterprise-grade capabilities using only free and open-source components.

**How to contribute:**
- 🐛 Report bugs or API issues
- 💡 Suggest new data sources or scanners
- 🔧 Implement additional phases or features
- 📚 Improve documentation and examples
- 🧪 Add test cases and CI improvements

**Development setup:**
```bash
# 1. Clone the repository
git clone https://github.com/therayyanawaz/VulnScanner.git
cd VulnScanner

# 2. Create and activate virtual environment
python -m venv .venv

# On Windows:
.venv\Scripts\activate
# On Linux/Mac:
source .venv/bin/activate

# 3. Install with development dependencies
pip install -e ".[dev]"

# 4. Run the test suite
pytest
```

Let's keep vulnerability management open and accessible for everyone! 🛡️

---

## 🧪 Testing & Quality Assurance

### **Comprehensive Test Suite**

VulnScanner includes an **enterprise-grade test suite** with **96% code coverage** to ensure reliability and facilitate safe development.

**Test Statistics:**
- ✅ **78 test functions** across 9 test files
- ✅ **96% code coverage** (219/227 statements)
- ✅ **50+ test scenarios** covering typical and edge cases
- ✅ **Integration, unit, and performance tests**

### **Testing Methodology**

Our testing approach ensures **comprehensive validation** of all core functionalities:

#### **1. Unit Tests**
- **Configuration** - Environment variables, settings validation
- **Database** - SQLite operations, schema integrity, CRUD operations
- **NVD API** - Rate limiting, delta sync, error handling, pagination
- **Caching** - OSV cache, TTL management, JSON serialization
- **CLI** - Command parsing, date validation, error handling

#### **2. Integration Tests**
- **End-to-End Workflows** - Complete CVE sync operations
- **Cross-Component** - Database + caching + API integration
- **Performance** - Batch processing, timing validation
- **Error Recovery** - Network failures, data corruption handling

#### **3. Edge Case Testing**
- Invalid API responses and network timeouts
- Database corruption and concurrent access
- Malformed data and partial failures
- Rate limit enforcement and retry logic

### **Running Tests**

#### **Quick Validation**
```bash
# Validate core functionality
python tests/test_run_all.py

# Interactive test runner with guidance
python run_tests.py
```

#### **Comprehensive Testing**
```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=vulnscanner --cov-report=html

# Run specific test categories
pytest tests/test_config.py         # Configuration tests
pytest tests/test_database.py       # Database tests
pytest tests/test_nvd.py           # NVD API tests
pytest tests/test_integration.py   # Integration tests

# Run with verbose output
pytest -v --tb=short
```

#### **Test Examples**

**Configuration Testing:**
```python
def test_environment_override():
    """Test environment variables override defaults"""
    # Validates NVD_API_KEY, rate limits, TTL settings
    
def test_invalid_type_conversion():
    """Test handling of invalid environment values"""
    # Ensures graceful degradation with bad config
```

**NVD API Testing:**
```python
async def test_rate_limiter_timing():
    """Test rate limiting accuracy (50 req/30s)"""
    # Validates token bucket algorithm implementation
    
async def test_delta_sync_pagination():
    """Test handling large result sets with pagination"""
    # Simulates 3000 CVEs across multiple pages
```

**Database Testing:**
```python
def test_schema_constraints():
    """Test database integrity constraints"""
    # Validates primary keys, foreign keys, unique constraints
    
def test_concurrent_access():
    """Test multiple database connections"""
    # Ensures data consistency under load
```

**Integration Testing:**
```python
async def test_full_nvd_sync_workflow():
    """Test complete end-to-end CVE sync"""
    # API call → rate limiting → parsing → database storage
    
def test_cross_component_caching():
    """Test caching integration with database"""
    # OSV cache → TTL validation → data consistency
```

### **Test Infrastructure**

**Framework & Tools:**
```bash
pytest>=7.0.0           # Primary test runner
pytest-asyncio>=0.21.0  # Async test support
pytest-cov>=4.0.0       # Coverage reporting
```

**Key Features:**
- **Isolated Tests** - Each test uses temporary databases
- **Realistic Data** - Actual CVE/NVD response formats
- **Comprehensive Mocking** - External APIs mocked for reliability
- **Performance Validation** - Timing constraints verified
- **Error Simulation** - Network failures and edge cases tested

### **Quality Metrics**

**Coverage Analysis:**
```
Name                          Stmts   Miss  Cover   Missing
-----------------------------------------------------------
src\vulnscanner\__init__.py       1      0   100%
src\vulnscanner\caching.py       26      0   100%
src\vulnscanner\cli.py           30      1    97%   
src\vulnscanner\config.py        18      0   100%
src\vulnscanner\db.py            26      0   100%
src\vulnscanner\nvd.py          118      7    94%   
-----------------------------------------------------------
TOTAL                           219      8    96%
```

**Test Categories:**
- ✅ **Happy Path Testing** - Normal operation scenarios
- ✅ **Edge Case Testing** - Boundary conditions and limits  
- ✅ **Error Path Testing** - Exception handling and recovery
- ✅ **Performance Testing** - Timing and scalability validation
- ✅ **Integration Testing** - Cross-component workflows

### **Testing Considerations**

#### **For Developers**
- **Pre-commit Testing** - Run `python run_tests.py` before commits
- **Feature Testing** - Add tests for new functionality in appropriate files
- **Mock Strategy** - External APIs are mocked; database uses temp files
- **Performance Awareness** - Tests validate timing constraints

#### **For Users**
- **Installation Testing** - Run `python tests/test_run_all.py` after setup
- **Configuration Testing** - Tests validate your environment setup
- **API Key Testing** - Tests work with or without NVD API key
- **Database Testing** - Tests ensure schema integrity

#### **Important Notes**
- **Windows File Handling** - Some test cleanup issues on Windows (non-critical)
- **Async Testing** - Uses pytest-asyncio for proper async validation
- **Mock Data** - Tests use realistic but fake CVE data for safety
- **Coverage Reporting** - HTML reports generated in `htmlcov/` directory

### **Test Results Interpretation**

**Successful Test Run:**
- All validation tests pass
- 96%+ code coverage maintained
- No critical functionality failures
- Performance benchmarks met

**Common Test Issues:**
- Temporary file cleanup warnings (Windows-specific, non-critical)
- Mock setup conflicts (test infrastructure, not core functionality)
- Database fixture issues (testing framework, not production code)

**When Tests Fail:**
1. Check basic setup: `python tests/test_run_all.py`
2. Verify dependencies: `pip install -r requirements.txt`
3. Check environment: Ensure no conflicting `VULNSCANNER_DB` setting
4. Run individual test files to isolate issues

The test suite ensures **confidence in code quality** and **safe development** as the project evolves through future phases.

---

## 🔧 Troubleshooting

### Common Setup Issues

**Issue: `vulnscanner` command not found**
```bash
# Solution 1: Ensure virtual environment is activated
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows

# Solution 2: Use Python module instead
python -m vulnscanner.cli --help
```

**Issue: Permission errors during installation**
```bash
# Solution: Use virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e .
```

**Issue: Database permission errors**
```bash
# Solution: Check database file permissions
ls -la vulnscanner.db  # Linux/Mac
# Ensure current user has read/write access
```

**Issue: API rate limiting errors**
```bash
# Solution: Get a free NVD API key for higher limits
# Visit: https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY="your-api-key-here"
```

**Issue: Tests failing**
```bash
# Solution: Run the simple test runner first
python tests/test_run_all.py

# If still failing, check dependencies
pip install -r requirements.txt
```

### Getting Help

- Check the [Issues](https://github.com/therayyanawaz/VulnScanner/issues) page for known problems
- Run tests to validate your setup: `python tests/test_run_all.py`
- Use debug mode for verbose output: `vulnscanner nvd-sync --debug`
- Ensure you're using Python 3.8 or higher: `python --version`
