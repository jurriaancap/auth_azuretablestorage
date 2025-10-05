"""
Tests for main FastAPI endpoints including authentication and MFA.
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch
from main import app


class TestAuthenticationEndpoints:
    """Test user authentication endpoints."""
    
    def test_root_endpoint(self, client):
        """Test the root endpoint returns welcome message."""
        response = client.get("/")
        assert response.status_code == 200
        assert response.json() == {"message": "Welcome to the Auth API"}
    
    def test_favicon_endpoint(self, client):
        """Test the favicon endpoint."""
        response = client.get("/favicon.ico")
        assert response.status_code == 200
        assert response.json() == {"message": "No favicon available"}
    
    @patch('main.entity_exists')
    @patch('main.insert_entity')
    def test_register_user_success(self, mock_insert, mock_exists, client):
        """Test successful user registration."""
        mock_exists.return_value = False  # User doesn't exist
        mock_insert.return_value = True
        
        response = client.post("/users/", json={
            "email": "test@example.com",
            "password": "TestPassword123!"
        })
        
        assert response.status_code == 201
        assert response.json() == {"message": "User successfully created."}
        mock_exists.assert_called_once()
        mock_insert.assert_called_once()
    
    @patch('main.entity_exists')
    def test_register_user_email_exists(self, mock_exists, client):
        """Test user registration with existing email."""
        mock_exists.return_value = True  # User already exists
        
        response = client.post("/users/", json={
            "email": "existing@example.com",
            "password": "TestPassword123!"
        })
        
        assert response.status_code == 400
        assert "already in use" in response.json()["detail"]


class TestMFAEndpoints:
    """Test MFA-related endpoints."""
    
    @patch('main.decode_jwt_token')
    @patch('main.verify_user_password_with_entity')
    @patch('main.generate_totp_secret')
    @patch('main.generate_qr_base64')
    @patch('main.encrypt_totp_secret_with_password')
    def test_mfa_register_success(self, mock_encrypt, mock_qr, mock_secret, 
                                  mock_verify, mock_decode, client):
        """Test successful MFA registration."""
        # Setup mocks
        mock_decode.return_value = {"email": "test@example.com"}
        mock_verify.return_value = (True, {"email": "test@example.com"})
        mock_secret.return_value = "TESTSECRET123"
        mock_qr.return_value = ("base64qr", "otpauth://uri")
        mock_encrypt.return_value = "encrypted_secret"
        
        response = client.post(
            "/users/test@example.com/mfa/register",
            json={"password": "TestPassword123!"},
            headers={"Authorization": "Bearer valid_token"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "qr_base64" in data
        assert "provisioning_uri" in data
    
    @patch('main.decode_jwt_token')
    @patch('main.verify_user_password_with_entity')
    def test_mfa_register_invalid_password(self, mock_verify, mock_decode, client):
        """Test MFA registration with invalid password."""
        mock_decode.return_value = {"email": "test@example.com"}
        mock_verify.return_value = (False, None)  # Invalid password
        
        response = client.post(
            "/users/test@example.com/mfa/register",
            json={"password": "wrongpassword"},
            headers={"Authorization": "Bearer valid_token"}
        )
        
        assert response.status_code == 401
        assert "Invalid password" in response.json()["detail"]


class TestLoginEndpoint:
    """Test login functionality."""
    
    @patch('main.get_entity')
    @patch('main.bcrypt.checkpw')
    @patch('main.create_jwt_token')
    def test_login_without_mfa(self, mock_jwt, mock_bcrypt, mock_get, client):
        """Test login for user without MFA enabled."""
        # Setup mocks
        mock_get.return_value = {
            "email": "test@example.com",
            "password_hash": "bW9ja19oYXNoX3ZhbHVl"  # base64 encoded "mock_hash_value"
        }
        mock_bcrypt.return_value = True
        mock_jwt.return_value = "mock_token"
        
        response = client.post("/login/", json={
            "email": "test@example.com",
            "password": "TestPassword123!"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["mfa_required"] is False
    
    @patch('main.get_entity')
    @patch('main.bcrypt.checkpw')
    @patch('main.decrypt_totp_secret_with_password')
    @patch('main.verify_totp_code')
    @patch('main.create_jwt_token')
    def test_login_with_mfa_success(self, mock_jwt, mock_verify_totp, 
                                   mock_decrypt, mock_bcrypt, mock_get, client):
        """Test successful login with MFA."""
        # Setup mocks
        mock_get.return_value = {
            "email": "test@example.com",
            "password_hash": "bW9ja19oYXNoX3ZhbHVl",  # base64 encoded
            "totp_secret": "encrypted_secret"
        }
        mock_bcrypt.return_value = True
        mock_decrypt.return_value = "decrypted_secret"
        mock_verify_totp.return_value = True
        mock_jwt.return_value = "mock_token"
        
        response = client.post("/login/", json={
            "email": "test@example.com",
            "password": "TestPassword123!",
            "code": "123456"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["mfa_required"] is True
    
    @patch('main.get_entity')
    @patch('main.bcrypt.checkpw')
    def test_login_with_mfa_missing_code(self, mock_bcrypt, mock_get, client):
        """Test login with MFA enabled but no code provided."""
        mock_get.return_value = {
            "email": "test@example.com",
            "password_hash": "bW9ja19oYXNoX3ZhbHVl",  # base64 encoded
            "totp_secret": "encrypted_secret"
        }
        mock_bcrypt.return_value = True
        
        response = client.post("/login/", json={
            "email": "test@example.com",
            "password": "TestPassword123!"
            # Missing "code" field
        })
        
        assert response.status_code == 400
        assert "MFA code required" in response.json()["detail"]


class TestPasswordChange:
    """Test password change functionality."""
    
    @patch('main.decode_jwt_token')
    @patch('main.get_entity')
    @patch('main.bcrypt.checkpw')
    @patch('main.update_entity')
    def test_password_change_without_mfa(self, mock_update, mock_bcrypt, 
                                        mock_get, mock_decode, client):
        """Test password change for user without MFA."""
        # Setup mocks
        mock_decode.return_value = {"email": "test@example.com"}
        mock_get.return_value = {
            "email": "test@example.com",
            "password_hash": "bW9ja19vbGRfaGFzaA=="  # base64 encoded "mock_old_hash"
        }
        mock_bcrypt.return_value = True
        mock_update.return_value = True
        
        response = client.post(
            "/users/test@example.com/change-password",
            json={
                "current_password": "OldPassword123!",
                "new_password": "NewPassword456!"
            },
            headers={"Authorization": "Bearer valid_token"}
        )
        
        assert response.status_code == 200
        assert "Password changed successfully" in response.json()["message"]
    
    @patch('main.decode_jwt_token')
    @patch('main.get_entity')
    @patch('main.bcrypt.checkpw')
    @patch('main.decrypt_totp_secret_with_password')
    @patch('main.encrypt_totp_secret_with_password')
    @patch('main.update_entity')
    def test_password_change_with_mfa(self, mock_update, mock_encrypt, mock_decrypt,
                                     mock_bcrypt, mock_get, mock_decode, client):
        """Test password change for user with MFA (re-encryption)."""
        # Setup mocks
        mock_decode.return_value = {"email": "test@example.com"}
        mock_get.return_value = {
            "email": "test@example.com",
            "password_hash": "bW9ja19vbGRfaGFzaA==",  # base64 encoded 
            "totp_secret": "old_encrypted_secret"
        }
        mock_bcrypt.return_value = True
        mock_decrypt.return_value = "decrypted_totp_secret"
        mock_encrypt.return_value = "new_encrypted_secret"
        mock_update.return_value = True
        
        response = client.post(
            "/users/test@example.com/change-password",
            json={
                "current_password": "OldPassword123!",
                "new_password": "NewPassword456!"
            },
            headers={"Authorization": "Bearer valid_token"}
        )
        
        assert response.status_code == 200
        assert "Password changed successfully" in response.json()["message"]
        
        # Verify MFA secret was re-encrypted
        mock_decrypt.assert_called_once()
        mock_encrypt.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__])
