# Testing Guide

## Test Structure

This project follows Python testing best practices with a well-organized test suite:

```
tests/
├── __init__.py              # Makes tests a package
├── conftest.py             # Shared pytest fixtures  
├── test_main.py            # Tests for main.py endpoints
├── test_auth_helpers.py    # Tests for auth/helpers.py functions
├── test_auth_mfa.py        # Tests for auth/mfa.py functions  
├── test_integration.py     # End-to-end integration tests
└── README.md              # This file
```

## Running Tests

### Install Test Dependencies
```bash
# Install test dependencies
uv add --group dev pytest pytest-cov pytest-mock httpx

# Or if using pip
pip install pytest pytest-cov pytest-mock httpx
```

### Run All Tests
```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=auth --cov=main --cov-report=term-missing
```

### Run Specific Tests
```bash
# Run specific test file
pytest tests/test_main.py

# Run specific test class
pytest tests/test_main.py::TestAuthenticationEndpoints

# Run specific test method
pytest tests/test_main.py::TestAuthenticationEndpoints::test_register_user_success

# Run tests matching pattern
pytest -k "test_login"

# Run only unit tests (exclude integration)
pytest -m "not integration"
```

## Test Categories

### Unit Tests
- `test_auth_helpers.py` - Test individual helper functions
- `test_auth_mfa.py` - Test MFA utility functions
- Parts of `test_main.py` - Test individual endpoint logic

### Integration Tests  
- `test_integration.py` - Test complete user flows
- `test_main.py` endpoint tests - Test full API behavior

## Writing New Tests

### Test Naming Convention
- Files: `test_*.py` (e.g., `test_new_feature.py`)
- Classes: `Test*` (e.g., `TestUserManagement`)
- Methods: `test_*` (e.g., `test_create_user_success`)

### Example Test Structure
```python
class TestNewFeature:
    """Test new feature functionality."""
    
    def test_feature_success(self, client):
        """Test successful feature operation."""
        # Arrange
        # Act  
        # Assert
        
    def test_feature_failure(self, client):
        """Test feature failure scenarios."""
        # Test error cases
```

## Mocking Guidelines

- Mock external dependencies (Azure Storage, etc.)
- Use `@patch()` decorator for mocking functions
- Mock at the module level where functions are used
- Use fixtures in `conftest.py` for shared mocks

## Test Coverage Goals

- Aim for >90% code coverage
- Focus on critical paths (authentication, MFA, security)
- Test both success and failure scenarios
- Include edge cases and error handling

## CI/CD Integration

Add to your CI pipeline:
```yaml
- name: Run Tests
  run: |
    pytest --cov=auth --cov=main --cov-report=xml
    
- name: Upload Coverage
  uses: codecov/codecov-action@v3
```