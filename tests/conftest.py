"""
Shared pytest fixtures and configuration for all tests.
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch

# Import your app
from main import app


@pytest.fixture
def client():
    """FastAPI test client fixture."""
    return TestClient(app)


@pytest.fixture
def mock_users_client():
    """Mock Azure Table Storage client for testing."""
    return Mock()


@pytest.fixture
def test_user_data():
    """Sample test user data."""
    return {
        "email": "test@example.com",
        "password": "testpassword123",
        "password_hash": "mock_bcrypt_hash"
    }


@pytest.fixture
def test_mfa_data():
    """Sample MFA test data."""
    return {
        "secret": "JBSWY3DPEHPK3PXP",
        "code": "123456",
        "encrypted_secret": "mock:encrypted:secret"
    }


@pytest.fixture
def mock_jwt_token():
    """Mock JWT token for authenticated requests."""
    return "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJleHAiOjk5OTk5OTk5OTl9.mock_signature"


@pytest.fixture(autouse=True)
def mock_azure_storage():
    """Automatically mock Azure Storage for all tests."""
    with patch('auth.db_helpers.connect_to_table') as mock_connect:
        mock_client = Mock()
        mock_connect.return_value = mock_client
        yield mock_client