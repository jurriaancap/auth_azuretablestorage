"""
Tests for auth.helpers module functions.
"""
import base64
from unittest.mock import Mock, patch
from auth.helpers import (
    b64e, b64d, derive_key_from_password, 
    encrypt_with_key, decrypt_with_key,
    verify_user_password_with_entity
)


class TestBase64Functions:
    """Test base64 encoding/decoding functions."""
    
    def test_b64e_encode_bytes(self):
        """Test base64 encoding of bytes."""
        test_data = b"hello world"
        result = b64e(test_data)
        expected = base64.b64encode(test_data).decode("utf-8")
        assert result == expected
    
    def test_b64d_decode_string(self):
        """Test base64 decoding of string."""
        test_string = "aGVsbG8gd29ybGQ="  # "hello world" in base64
        result = b64d(test_string)
        expected = b"hello world"
        assert result == expected
    
    def test_b64e_b64d_roundtrip(self):
        """Test that encoding then decoding returns original data."""
        original = b"test data for roundtrip"
        encoded = b64e(original)
        decoded = b64d(encoded)
        assert decoded == original


class TestEncryptionFunctions:
    """Test encryption and decryption functions."""
    
    def test_derive_key_from_password(self):
        """Test password-based key derivation."""
        password = "testpassword123"
        salt = b"testsalt12345678"  # 16 bytes
        
        key = derive_key_from_password(password, salt)
        
        assert isinstance(key, bytes)
        assert len(key) == 32  # 256 bits
    
    def test_derive_key_consistent(self):
        """Test that same password+salt produces same key."""
        password = "testpassword123"
        salt = b"testsalt12345678"
        
        key1 = derive_key_from_password(password, salt)
        key2 = derive_key_from_password(password, salt)
        
        assert key1 == key2
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test that encryption then decryption returns original text."""
        key = b"a" * 32  # 32-byte key
        plaintext = "This is a secret message"
        
        # Encrypt
        nonce, ciphertext, tag = encrypt_with_key(key, plaintext)
        
        # Verify we get back base64 strings
        assert isinstance(nonce, str)
        assert isinstance(ciphertext, str)
        assert isinstance(tag, str)
        
        # Decrypt
        decrypted = decrypt_with_key(key, nonce, ciphertext, tag)
        
        assert decrypted == plaintext
    
    def test_encrypt_different_nonce_each_time(self):
        """Test that encryption produces different nonce each time."""
        key = b"a" * 32
        plaintext = "same message"
        
        nonce1, _, _ = encrypt_with_key(key, plaintext)
        nonce2, _, _ = encrypt_with_key(key, plaintext)
        
        assert nonce1 != nonce2


class TestPasswordVerification:
    """Test password verification with user entity retrieval."""
    
    @patch('auth.db_helpers.get_entity')
    @patch('auth.helpers.bcrypt.checkpw')
    def test_verify_user_password_with_entity_success(self, mock_checkpw, mock_get_entity):
        """Test successful password verification with entity retrieval."""
        # Setup mocks
        mock_entity = {
            "email": "test@example.com",
            "password_hash": "bW9ja19oYXNo"  # base64 encoded "mock_hash"
        }
        mock_get_entity.return_value = mock_entity
        mock_checkpw.return_value = True
        
        # Create a mock client
        mock_client = Mock()
        
        # Test
        is_valid, user_entity = verify_user_password_with_entity(
            "test@example.com", 
            "testpassword", 
            mock_client, 
            "users"
        )
        
        assert is_valid is True
        assert user_entity == mock_entity
        mock_get_entity.assert_called_once_with(mock_client, "users", "test@example.com")
        mock_checkpw.assert_called_once()
    
    @patch('auth.db_helpers.get_entity')
    def test_verify_user_password_with_entity_user_not_found(self, mock_get_entity):
        """Test password verification when user doesn't exist."""
        mock_get_entity.return_value = None
        mock_client = Mock()
        
        is_valid, user_entity = verify_user_password_with_entity(
            "nonexistent@example.com", 
            "testpassword", 
            mock_client, 
            "users"
        )
        
        assert is_valid is False
        assert user_entity is None
    
    @patch('auth.db_helpers.get_entity')
    @patch('auth.helpers.bcrypt.checkpw')
    def test_verify_user_password_with_entity_wrong_password(self, mock_checkpw, mock_get_entity):
        """Test password verification with wrong password."""
        mock_entity = {
            "email": "test@example.com",
            "password_hash": "bW9ja19oYXNo"
        }
        mock_get_entity.return_value = mock_entity
        mock_checkpw.return_value = False  # Wrong password
        mock_client = Mock()
        
        is_valid, user_entity = verify_user_password_with_entity(
            "test@example.com", 
            "wrongpassword", 
            mock_client, 
            "users"
        )
        
        assert is_valid is False
        assert user_entity == mock_entity  # Entity still returned