"""
Tests for data validation in Pydantic models.
Covers password validation, email validation, and TOTP code validation.
"""

import pytest
from pydantic import ValidationError
from auth.classes import (
    UserCreate,
    UserLogin,
    PasswordChangeRequest,
    MFAVerifyRequest,
    MFAValidateRequest
)


class TestPasswordValidation:
    """Test password validation rules for UserCreate and PasswordChangeRequest."""

    def test_valid_passwords(self):
        """Test that valid passwords pass validation."""
        valid_passwords = [
            "Password1!",
            "MySecureP@ssw0rd",
            "Complex123#Password",
            "Str0ng!Pa$$word",
            "A1b2C3d4!",  # Minimum complexity
            "VeryLongPasswordWithNumbers123AndSymbols!@#",  # Long password
            "P@ssw0rd" + "x" * 110,  # Near max length (120 chars)
        ]
        
        for password in valid_passwords:
            # Test UserCreate
            user = UserCreate(email="test@example.com", password=password)
            assert user.password == password
            
            # Test PasswordChangeRequest new_password
            change_req = PasswordChangeRequest(
                current_password="OldP@ssw0rd1",
                new_password=password
            )
            assert change_req.new_password == password

    def test_password_too_short(self):
        """Test that passwords under 8 characters are rejected."""
        short_passwords = ["", "a", "Ab1!", "Short1!", "1234567"]
        
        for password in short_passwords:
            with pytest.raises(ValidationError) as exc_info:
                UserCreate(email="test@example.com", password=password)
            # Pydantic Field(min_length=8) handles this with its own message
            assert "at least 8 characters" in str(exc_info.value).lower()
            
            with pytest.raises(ValidationError) as exc_info:
                PasswordChangeRequest(
                    current_password="OldPassword123!",
                    new_password=password
                )
            assert "at least 8 characters" in str(exc_info.value).lower()

    def test_password_too_long(self):
        """Test that passwords over 128 characters are rejected."""
        long_password = "P@ssw0rd1" + "x" * 130  # 139 characters
        
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(email="test@example.com", password=long_password)
        # Pydantic Field(max_length=128) handles this with its own message
        assert "at most 128 characters" in str(exc_info.value).lower()
        
        with pytest.raises(ValidationError) as exc_info:
            PasswordChangeRequest(
                current_password="OldPassword123!",
                new_password=long_password
            )
        assert "at most 128 characters" in str(exc_info.value).lower()

    def test_password_missing_uppercase(self):
        """Test that passwords without uppercase letters are rejected."""
        passwords_no_upper = ["password1!", "mypassword@123", "lowercase1#"]
        
        for password in passwords_no_upper:
            with pytest.raises(ValidationError) as exc_info:
                UserCreate(email="test@example.com", password=password)
            assert ("Password must contain at least one uppercase letter, one lowercase letter, "
                    "one digit, one special character") in str(exc_info.value)

    def test_password_missing_lowercase(self):
        """Test that passwords without lowercase letters are rejected."""
        passwords_no_lower = ["PASSWORD1!", "MYPASSWORD@123", "UPPERCASE1#"]
        
        for password in passwords_no_lower:
            with pytest.raises(ValidationError) as exc_info:
                UserCreate(email="test@example.com", password=password)
            assert ("Password must contain at least one uppercase letter, one lowercase letter, "
                    "one digit, one special character") in str(exc_info.value)

    def test_password_missing_digit(self):
        """Test that passwords without digits are rejected."""
        passwords_no_digit = ["Password!", "MyPassword@", "NoNumbers#"]
        
        for password in passwords_no_digit:
            with pytest.raises(ValidationError) as exc_info:
                UserCreate(email="test@example.com", password=password)
            assert ("Password must contain at least one uppercase letter, one lowercase letter, "
                    "one digit, one special character") in str(exc_info.value)

    def test_password_missing_special_character(self):
        """Test that passwords without special characters are rejected."""
        passwords_no_special = ["Password1", "MyPassword123", "NoSpecialChars1"]
        
        for password in passwords_no_special:
            with pytest.raises(ValidationError) as exc_info:
                UserCreate(email="test@example.com", password=password)
            assert ("Password must contain at least one uppercase letter, one lowercase letter, "
                    "one digit, one special character") in str(exc_info.value)

    def test_password_edge_cases(self):
        """Test edge cases for password validation."""
        # Exactly 8 characters with all requirements
        min_valid = "A1b2C3d!"
        user = UserCreate(email="test@example.com", password=min_valid)
        assert user.password == min_valid
        
        # Exactly 128 characters with all requirements
        max_valid = "A1b!" + "x" * 124  # 128 total
        user = UserCreate(email="test@example.com", password=max_valid)
        assert user.password == max_valid

    def test_all_special_characters_accepted(self):
        """Test that all defined special characters are accepted."""
        special_chars = "!@#$%^&*(),.?\":{}|<>"
        for char in special_chars:
            password = f"Password1{char}"
            user = UserCreate(email="test@example.com", password=password)
            assert user.password == password


class TestEmailValidation:
    """Test email validation rules for UserCreate."""

    def test_valid_emails(self):
        """Test that valid emails pass validation."""
        valid_emails = [
            "test@example.com",
            "user.name@domain.co.uk",
            "first.last+tag@company.org",
            "numbers123@test.io",
            "simple@domain.com",
            "long.email.address@very-long-domain-name.example.com",
        ]
        
        for email in valid_emails:
            user = UserCreate(email=email, password="ValidPassword1!")
            assert str(user.email) == email

    def test_invalid_email_formats(self):
        """Test that invalid email formats are rejected."""
        invalid_emails = [
            "not-an-email",
            "@domain.com",
            "user@",
            "user..double@domain.com",  # Consecutive dots
            "user@domain",
            "",
        ]
        
        for email in invalid_emails:
            with pytest.raises(ValidationError):
                UserCreate(email=email, password="ValidPassword1!")

    def test_email_too_long(self):
        """Test that emails over 254 characters are rejected."""
        # EmailStr validates before our custom validator, so very long emails
        # are rejected by Pydantic's built-in validation first
        too_long_email = "a" * 250 + "@example.com"  # 261 chars
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(email=too_long_email, password="ValidPassword1!")
        # EmailStr rejects this before our custom validator runs
        assert "email address" in str(exc_info.value).lower()

    def test_email_consecutive_dots(self):
        """Test that emails with consecutive dots are rejected."""
        emails_with_consecutive_dots = [
            "user..name@domain.com",
            "test@domain..com", 
            "user...test@example.org",
        ]
        
        for email in emails_with_consecutive_dots:
            with pytest.raises(ValidationError) as exc_info:
                UserCreate(email=email, password="ValidPassword1!")
            # EmailStr handles this validation with its own message
            assert "email address" in str(exc_info.value).lower()


class TestTOTPCodeValidation:
    """Test TOTP code validation rules."""

    def test_valid_totp_codes(self):
        """Test that valid 6-digit TOTP codes pass validation."""
        valid_codes = ["123456", "000000", "999999", "123000", "000123"]
        
        for code in valid_codes:
            # Test UserLogin with code
            login = UserLogin(
                email="test@example.com",
                password="password",
                code=code
            )
            assert login.code == code
            
            # Test MFAVerifyRequest
            verify = MFAVerifyRequest(
                password="password",
                secret="ABCDEFGHIJK",
                code=code
            )
            assert verify.code == code
            
            # Test MFAValidateRequest
            validate = MFAValidateRequest(
                password="password",
                code=code
            )
            assert validate.code == code

    def test_totp_code_none_allowed_in_login(self):
        """Test that None TOTP code is allowed in UserLogin."""
        login = UserLogin(
            email="test@example.com",
            password="password",
            code=None
        )
        assert login.code is None

    def test_invalid_totp_codes(self):
        """Test that invalid TOTP codes are rejected."""
        invalid_codes = [
            "12345",      # Too short
            "1234567",    # Too long
            "12345a",     # Contains letter
            "abcdef",     # All letters
            "123 456",    # Contains space
            "123-456",    # Contains dash
            "",           # Empty string
            "123.456",    # Contains dot
        ]
        
        for code in invalid_codes:
            # Test UserLogin
            with pytest.raises(ValidationError) as exc_info:
                UserLogin(
                    email="test@example.com",
                    password="password",
                    code=code
                )
            assert "must be exactly 6 digits" in str(exc_info.value)
            
            # Test MFAVerifyRequest
            with pytest.raises(ValidationError) as exc_info:
                MFAVerifyRequest(
                    password="password",
                    secret="ABCDEFGHIJK",
                    code=code
                )
            assert "must be exactly 6 digits" in str(exc_info.value)
            
            # Test MFAValidateRequest
            with pytest.raises(ValidationError) as exc_info:
                MFAValidateRequest(
                    password="password",
                    code=code
                )
            assert "must be exactly 6 digits" in str(exc_info.value)

    def test_totp_edge_cases(self):
        """Test edge cases for TOTP validation."""
        # Leading zeros should be preserved
        code_with_zeros = "000123"
        login = UserLogin(
            email="test@example.com",
            password="password",
            code=code_with_zeros
        )
        assert login.code == "000123"


class TestModelIntegration:
    """Test complete model validation with multiple fields."""

    def test_user_create_complete_validation(self):
        """Test UserCreate with both email and password validation."""
        # Valid case
        user = UserCreate(
            email="test@example.com",
            password="ValidPassword1!"
        )
        assert str(user.email) == "test@example.com"
        assert user.password == "ValidPassword1!"
        
        # Invalid email, valid password
        with pytest.raises(ValidationError):
            UserCreate(
                email="invalid-email",
                password="ValidPassword1!"
            )
        
        # Valid email, invalid password
        with pytest.raises(ValidationError):
            UserCreate(
                email="test@example.com",
                password="weak"
            )

    def test_password_change_validation(self):
        """Test PasswordChangeRequest validation."""
        # Valid case
        change = PasswordChangeRequest(
            current_password="oldpassword",  # No validation on current
            new_password="NewValidPassword1!"
        )
        assert change.current_password == "oldpassword"
        assert change.new_password == "NewValidPassword1!"
        
        # Invalid new password
        with pytest.raises(ValidationError) as exc_info:
            PasswordChangeRequest(
                current_password="oldpassword",
                new_password="weak"
            )
        # "weak" is caught by Field length validation before custom validator
        assert ("New password must" in str(exc_info.value) or 
                "at least 8 characters" in str(exc_info.value))

    def test_mfa_requests_validation(self):
        """Test MFA request models validation."""
        # Valid MFAVerifyRequest
        verify = MFAVerifyRequest(
            password="anypassword",
            secret="TESTSECRET",
            code="123456"
        )
        assert verify.password == "anypassword"
        assert verify.secret == "TESTSECRET"
        assert verify.code == "123456"
        
        # Invalid TOTP code
        with pytest.raises(ValidationError):
            MFAVerifyRequest(
                password="anypassword",
                secret="TESTSECRET",
                code="invalid"
            )