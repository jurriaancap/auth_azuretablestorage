"""
Integration tests for complete authentication flows.
"""
from unittest.mock import patch, Mock


class TestFullAuthenticationFlow:
    """Test complete user registration → MFA setup → login flow."""
    
    @patch('main.entity_exists')
    @patch('main.insert_entity')
    @patch('main.decode_jwt_token')
    @patch('main.verify_user_password_with_entity')
    @patch('main.generate_totp_secret')
    @patch('main.generate_qr_base64')
    @patch('main.encrypt_totp_secret_with_password')
    @patch('main.verify_totp_code')
    @patch('main.update_entity')
    @patch('main.get_entity')
    @patch('main.bcrypt.checkpw')
    @patch('main.decrypt_totp_secret_with_password')
    @patch('main.create_jwt_token')
    def test_complete_user_journey_with_mfa(
        self, mock_jwt, mock_decrypt, mock_bcrypt_check, mock_get_login,
        mock_update, mock_verify_totp, mock_encrypt, mock_qr, mock_secret,
        mock_verify_password, mock_decode, mock_insert, mock_exists, client
    ):
        """Test complete user journey: register → MFA setup → login."""
        
        # Step 1: User Registration
        mock_exists.return_value = False
        mock_insert.return_value = True
        
        register_response = client.post("/users/", json={
            "email": "newuser@example.com",
            "password": "securepassword123"
        })
        assert register_response.status_code == 201
        
        # Step 2: MFA Registration
        mock_decode.return_value = {"email": "newuser@example.com"}
        mock_verify_password.return_value = (True, {"email": "newuser@example.com"})
        mock_secret.return_value = "NEWSECRET123"
        mock_qr.return_value = ("qr_base64", "otpauth://uri")
        mock_encrypt.return_value = "encrypted_secret"
        
        mfa_register_response = client.post(
            "/users/newuser@example.com/mfa/register",
            json={"password": "securepassword123"},
            headers={"Authorization": "Bearer valid_token"}
        )
        assert mfa_register_response.status_code == 200
        
        # Step 3: MFA Verification (complete setup)
        mock_verify_totp.return_value = True
        mock_update.return_value = True
        
        mfa_verify_response = client.post(
            "/users/newuser@example.com/mfa/verify",
            json={
                "password": "securepassword123",
                "secret": "NEWSECRET123",
                "code": "123456"
            },
            headers={"Authorization": "Bearer valid_token"}
        )
        assert mfa_verify_response.status_code == 200
        
        # Step 4: Login with MFA
        mock_get_login.return_value = {
            "email": "newuser@example.com",
            "password_hash": "hash",
            "totp_secret": "encrypted_secret"
        }
        mock_bcrypt_check.return_value = True
        mock_decrypt.return_value = "NEWSECRET123"
        mock_verify_totp.return_value = True
        mock_jwt.return_value = "access_token"
        
        login_response = client.post("/login/", json={
            "email": "newuser@example.com",
            "password": "securepassword123",
            "code": "654321"
        })
        assert login_response.status_code == 200
        login_data = login_response.json()
        assert login_data["mfa_required"] is True
        assert "access_token" in login_data


class TestPasswordChangeFlow:
    """Test password change with MFA preservation."""
    
    @patch('main.decode_jwt_token')
    @patch('main.get_entity')
    @patch('main.bcrypt.checkpw')
    @patch('main.decrypt_totp_secret_with_password')
    @patch('main.encrypt_totp_secret_with_password')
    @patch('main.update_entity')
    def test_password_change_preserves_mfa(
        self, mock_update, mock_encrypt, mock_decrypt, mock_bcrypt,
        mock_get, mock_decode, client
    ):
        """Test that password change preserves MFA functionality."""
        
        # Setup: User with MFA enabled
        mock_decode.return_value = {"email": "user@example.com"}
        mock_get.return_value = {
            "email": "user@example.com", 
            "password_hash": "bW9ja19vbGRfaGFzaA==",  # base64 encoded "mock_old_hash"
            "totp_secret": "old_encrypted_secret"
        }
        mock_bcrypt.return_value = True
        mock_decrypt.return_value = "PRESERVED_SECRET"
        mock_encrypt.return_value = "new_encrypted_secret"
        mock_update.return_value = True
        
        # Change password
        response = client.post(
            "/users/user@example.com/change-password",
            json={
                "current_password": "oldpassword123",
                "new_password": "newpassword456"
            },
            headers={"Authorization": "Bearer valid_token"}
        )
        
        assert response.status_code == 200
        
        # Verify MFA secret was decrypted with old password
        mock_decrypt.assert_called_with(
            "old_encrypted_secret", "oldpassword123", "user@example.com"
        )
        
        # Verify MFA secret was re-encrypted with new password  
        mock_encrypt.assert_called_with(
            "PRESERVED_SECRET", "newpassword456", "user@example.com"
        )
        
        # Verify both password and MFA secret were updated
        call_args = mock_update.call_args[1]
        assert "password_hash" in call_args
        assert call_args["totp_secret"] == "new_encrypted_secret"


class TestErrorHandling:
    """Test error handling scenarios."""
    
    @patch('main.get_entity')
    def test_login_with_nonexistent_user(self, mock_get, client):
        """Test login attempt with non-existent user."""
        mock_get.return_value = None
        
        response = client.post("/login/", json={
            "email": "nonexistent@example.com",
            "password": "anypassword"
        })
        
        assert response.status_code == 401
        assert "Invalid username or password" in response.json()["detail"]
    
    @patch('main.decode_jwt_token')
    def test_mfa_operations_with_invalid_token(self, mock_decode, client):
        """Test MFA operations with invalid JWT token."""
        mock_decode.side_effect = Exception("Invalid token")
        
        response = client.post(
            "/users/test@example.com/mfa/register",
            json={"password": "testpassword"},
            headers={"Authorization": "Bearer invalid_token"}
        )
        
        assert response.status_code == 401
        assert "Invalid token" in response.json()["detail"]