# 🔧 GitHub Repository Setup Guide

This guide helps you configure the repository for automated CI/CD and releases.

## 🚀 Quick Setup Checklist

### 1. Repository Settings
- [ ] Enable **Issues** and **Pull Requests**
- [ ] Set **main** as the default branch
- [ ] Enable **branch protection** for main branch
- [ ] Require **status checks** before merging

### 2. Branch Protection Rules
Configure branch protection for `main`:
- [ ] Require pull request reviews (minimum 1)
- [ ] Require status checks to pass: `🔍 Code Quality`, `🧪 Test Matrix`
- [ ] Require branches to be up to date
- [ ] Include administrators in restrictions

### 3. Repository Secrets
Add these secrets in **Settings → Secrets and variables → Actions**:

| Secret Name | Description | Required For |
|-------------|-------------|--------------|
| `PYPI_API_TOKEN` | PyPI API token for publishing | Release workflow |
| `TEST_PYPI_API_TOKEN` | Test PyPI API token | Release workflow |
| `CODECOV_TOKEN` | Codecov token for coverage | CI workflow |

### 4. Environment Setup
Create these environments in **Settings → Environments**:

#### `pypi` Environment
- **Deployment branches**: Tags only (`v*.*.*`)
- **Environment secrets**: `PYPI_API_TOKEN`
- **Required reviewers**: Repository maintainers

#### `testpypi` Environment  
- **Deployment branches**: `main` branch only
- **Environment secrets**: `TEST_PYPI_API_TOKEN`
- **Required reviewers**: None (auto-deploy)

### 5. PyPI Setup
1. **Create PyPI Account**: https://pypi.org/account/register/
2. **Create API Token**: https://pypi.org/manage/account/token/
3. **Create Test PyPI Account**: https://test.pypi.org/account/register/
4. **Create Test API Token**: https://test.pypi.org/manage/account/token/

### 6. Codecov Setup (Optional)
1. **Sign up**: https://codecov.io/ with your GitHub account
2. **Add repository**: Enable VulnScanner repository
3. **Get token**: Copy the repository token
4. **Add secret**: `CODECOV_TOKEN` in repository secrets

## 📋 Workflow Overview

### 🔄 Continuous Integration (`ci.yml`)
**Triggers**: PRs, pushes to main/develop
- Code quality checks (linting, formatting, type checking)
- Test matrix across Python 3.10, 3.11, 3.12 on Ubuntu, Windows, macOS
- Installation testing
- Performance benchmarks
- Documentation validation
- Security scanning

### 🚀 Release Pipeline (`release.yml`)
**Triggers**: Tags (`v*.*.*`), main branch pushes, manual dispatch
- Quality assurance across multiple Python versions
- Security scanning with multiple tools
- Package building and validation
- Cross-platform integration testing
- PyPI publishing (tags) / Test PyPI (main branch)
- GitHub release creation with auto-generated notes
- Post-release validation

## 🏷️ Release Process

### 1. Prepare Release
```bash
# Update version in pyproject.toml
# Update CHANGELOG.md
# Commit changes
git add .
git commit -m "chore: prepare release v1.0.0"
git push origin main
```

### 2. Create Release Tag
```bash
# Create and push tag
git tag v1.0.0
git push origin v1.0.0
```

### 3. Monitor Workflow
- Check **Actions** tab for workflow progress
- Verify tests pass on all platforms
- Confirm package publishes to PyPI
- Review auto-generated GitHub release

### 4. Manual Release (Alternative)
Use **Actions → Release Package → Run workflow**:
- Specify version (e.g., `1.0.0`)
- Choose if pre-release
- Trigger manually

## 🔧 Workflow Configuration

### Environment Variables
```yaml
PYTHON_VERSION: '3.11'      # Primary Python version
PACKAGE_NAME: 'vulnscanner' # Package name for coverage
REGISTRY_URL: 'https://pypi.org/simple/'
```

### Matrix Testing
- **OS**: Ubuntu, Windows, macOS
- **Python**: 3.10, 3.11, 3.12
- **Fail-fast**: Disabled (continue testing other combinations)

### Security Features
- **Trusted publishing** to PyPI (no API keys in workflow)
- **Environment protection** for production releases
- **Security scanning** with Bandit, Safety, Semgrep
- **Dependency auditing** with pip-audit

## 🎯 Workflow Jobs Summary

### CI Workflow Jobs
1. **🔍 Code Quality** - Linting and formatting
2. **🧪 Test Matrix** - Cross-platform testing
3. **📦 Installation Test** - Package installation validation
4. **⚡ Performance Benchmark** - Performance regression detection
5. **📚 Documentation Check** - README and docstring validation
6. **🔒 Dependency Security** - Security vulnerability scanning
7. **📋 CI Summary** - Workflow results summary

### Release Workflow Jobs
1. **🧪 Quality Assurance** - Multi-version testing
2. **🔒 Security Scanning** - Comprehensive security analysis
3. **📦 Build Package** - Source and wheel building
4. **🧪 Integration Testing** - Cross-platform package testing
5. **🚀 Publish to PyPI** - Production package publishing
6. **🧪 Publish to Test PyPI** - Development package publishing
7. **📋 Create GitHub Release** - Release notes and artifacts
8. **✅ Post-Release Validation** - Verify PyPI deployment
9. **🧹 Cleanup & Notify** - Workflow summary and cleanup

## 🚨 Troubleshooting

### Common Issues

**PyPI Publishing Fails**
- Verify API token is correct and has upload permissions
- Check package name availability on PyPI
- Ensure version number follows semantic versioning

**Tests Fail on Specific Platform**
- Check platform-specific dependencies
- Review file path handling (Windows vs Unix)
- Verify environment variable handling

**Security Scan Failures**
- Review and address security vulnerabilities
- Update dependencies to secure versions
- Add security exceptions if false positives

**Coverage Upload Fails**
- Verify Codecov token is correct
- Check if repository is properly configured on Codecov
- Review coverage file generation

### Getting Help
- Check **Actions** logs for detailed error messages
- Review **Issues** for similar problems
- Consult the project README for additional guidance
- Create a new issue with detailed error information

## ✅ Verification Steps

After setup, verify everything works:

1. **Create test PR** with small change
2. **Check CI passes** all quality checks
3. **Merge to main** and verify Test PyPI publish
4. **Create test tag** and verify full release pipeline
5. **Check PyPI package** installs correctly

Your repository is now ready for automated CI/CD! 🎉
