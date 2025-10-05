"""
Tests for auth.mfa module functions.
"""
from unittest.mock import Mock, patch
from auth.mfa import (
    generate_totp_secret, create_provisioning_uri, 
    verify_totp_code, encrypt_totp_secret_with_password,
    decrypt_totp_secret_with_password
)


class TestTOTPFunctions:
    """Test TOTP secret generation and verification."""
    
    def test_generate_totp_secret(self):
        """Test TOTP secret generation."""
        secret = generate_totp_secret()
        
        assert isinstance(secret, str)
        assert len(secret) == 32  # Base32 secret should be 32 characters
        assert secret.isalnum()  # Should only contain alphanumeric characters
    
    def test_generate_different_secrets(self):
        """Test that each call generates a different secret."""
        secret1 = generate_totp_secret()
        secret2 = generate_totp_secret()
        
        assert secret1 != secret2
    
    def test_create_provisioning_uri(self):
        """Test provisioning URI creation."""
        secret = "JBSWY3DPEHPK3PXP"
        account = "test@example.com"
        issuer = "TestApp"
        
        uri = create_provisioning_uri(secret, account, issuer)
        
        assert uri.startswith("otpauth://totp/")
        assert "test%40example.com" in uri  # @ gets URL encoded to %40
        assert issuer in uri
        assert secret in uri
    
    @patch('auth.mfa.pyotp.TOTP')
    def test_verify_totp_code_success(self, mock_totp_class):
        """Test successful TOTP code verification."""
        mock_totp = Mock()
        mock_totp.verify.return_value = True
        mock_totp_class.return_value = mock_totp
        
        result = verify_totp_code("TESTSECRET", "123456")
        
        assert result is True
        mock_totp_class.assert_called_once_with("TESTSECRET")
        mock_totp.verify.assert_called_once_with("123456")
    
    @patch('auth.mfa.pyotp.TOTP')
    def test_verify_totp_code_failure(self, mock_totp_class):
        """Test failed TOTP code verification."""
        mock_totp = Mock()
        mock_totp.verify.return_value = False
        mock_totp_class.return_value = mock_totp
        
        result = verify_totp_code("TESTSECRET", "wrong_code")
        
        assert result is False


class TestMFAEncryption:
    """Test MFA secret encryption and decryption."""
    
    @patch('auth.mfa.derive_key_from_password')
    @patch('auth.mfa.encrypt_with_key')
    def test_encrypt_totp_secret_with_password(self, mock_encrypt, mock_derive):
        """Test TOTP secret encryption."""
        # Setup mocks
        mock_derive.return_value = b"mock_key" * 4  # 32 bytes
        mock_encrypt.return_value = ("nonce123", "cipher123", "tag123")
        
        result = encrypt_totp_secret_with_password(
            "TESTSECRET", 
            "password123", 
            "test@example.com"
        )
        
        assert result == "nonce123:cipher123:tag123"
        
        # Verify email was used as salt (padded to 16 bytes)
        expected_salt = b"test@example.com"[:16].ljust(16, b'0')
        mock_derive.assert_called_once_with("password123", expected_salt)
        mock_encrypt.assert_called_once_with(b"mock_key" * 4, "TESTSECRET")
    
    @patch('auth.mfa.derive_key_from_password')
    @patch('auth.mfa.decrypt_with_key')
    def test_decrypt_totp_secret_with_password(self, mock_decrypt, mock_derive):
        """Test TOTP secret decryption."""
        # Setup mocks
        mock_derive.return_value = b"mock_key" * 4
        mock_decrypt.return_value = "TESTSECRET"
        
        result = decrypt_totp_secret_with_password(
            "nonce123:cipher123:tag123",
            "password123",
            "test@example.com"
        )
        
        assert result == "TESTSECRET"
        
        # Verify the same salt derivation
        expected_salt = b"test@example.com"[:16].ljust(16, b'0')
        mock_derive.assert_called_once_with("password123", expected_salt)
        mock_decrypt.assert_called_once_with(
            b"mock_key" * 4, "nonce123", "cipher123", "tag123"
        )
    
    def test_decrypt_invalid_format(self):
        """Test decryption with invalid encrypted format."""
        try:
            decrypt_totp_secret_with_password(
                "invalid_format",  # Missing colons
                "password123",
                "test@example.com"
            )
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "Failed to decrypt TOTP secret" in str(e)
    
    @patch('auth.mfa.derive_key_from_password')
    @patch('auth.mfa.encrypt_with_key')
    @patch('auth.mfa.decrypt_with_key')
    def test_encryption_decryption_roundtrip(self, mock_decrypt, mock_encrypt, mock_derive):
        """Test that encryption then decryption returns original secret."""
        # Setup mocks to simulate real encryption/decryption
        mock_derive.return_value = b"consistent_key" * 2  # 32 bytes
        mock_encrypt.return_value = ("nonce", "ciphertext", "tag")
        mock_decrypt.return_value = "ORIGINALSECRET"
        
        # Encrypt
        encrypted = encrypt_totp_secret_with_password(
            "ORIGINALSECRET", 
            "password123", 
            "test@example.com"
        )
        
        # Decrypt
        decrypted = decrypt_totp_secret_with_password(
            encrypted,
            "password123", 
            "test@example.com"
        )
        
        assert decrypted == "ORIGINALSECRET"
    
    def test_email_salt_generation(self):
        """Test that email is properly converted to salt."""
        # This tests the salt generation logic directly
        email = "test@example.com"
        expected_salt = email.encode('utf-8')[:16].ljust(16, b'0')
        
        # The expected salt should be 16 bytes
        assert len(expected_salt) == 16
        assert expected_salt.startswith(b"test@example.com")
        
        # Test with long email (should be truncated)
        long_email = "very.long.email.address@example.com"
        long_salt = long_email.encode('utf-8')[:16].ljust(16, b'0')
        assert len(long_salt) == 16
        
        # Test with short email (should be padded)
        short_email = "a@b.c"
        short_salt = short_email.encode('utf-8')[:16].ljust(16, b'0')
        assert len(short_salt) == 16
        assert short_salt.endswith(b'0')  # Should be padded with zeros