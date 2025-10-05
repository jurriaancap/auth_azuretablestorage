# Example of how you could make it reusable (but your current approach is fine!)

from pydantic import field_validator
import re

def password_validator(field_name: str = "password"):
    """
    Reusable password validator factory.
    Returns a field_validator for password fields.
    """
    def _validate_password(cls, v):
        """
        Validate password meets security requirements:
        - 8-128 characters (NIST recommended range)
        - At least one uppercase letter
        - At least one lowercase letter  
        - At least one digit
        - At least one special character
        """
        if len(v) < 8:
            raise ValueError(f'{field_name.title()} must be at least 8 characters long')
        if len(v) > 128:
            raise ValueError(f'{field_name.title()} must be no more than 128 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError(f'{field_name.title()} must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError(f'{field_name.title()} must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError(f'{field_name.title()} must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError(f'{field_name.title()} must contain at least one special character (!@#$%^&*(),.?":{}|<>)')
        return v
    
    return field_validator(field_name)(_validate_password)

# Usage would be:
# class UserCreate(BaseModel):
#     password: str
#     validate_password = password_validator("password")