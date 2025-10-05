import bcrypt
from fastapi import FastAPI, HTTPException, Depends 
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timezone

## special import from my auth.helpers files
from auth.helpers import b64e, b64d, create_jwt_token, decode_jwt_token, verify_user_password_with_entity
from auth.db_helpers import connect_to_table, entity_exists, insert_entity, get_entity, delete_entity, update_entity
from auth.mfa import generate_totp_secret, generate_qr_base64, verify_totp_code, encrypt_totp_secret_with_password, decrypt_totp_secret_with_password

from auth.config import (
    ## import the variables from config.py 
    JWT_EXP_MINUTES,
    REFRESH_TOKEN_EXP_MINUTES, 
    USERS_TABLE_NAME,
    SAS_TOKEN,
    ENDPOINT,
)

## from auth/classes.py import the defined classes from the file
from auth.classes import (
    UserCreate, UserLogin, RefreshRequest, LoginResponse, UserDeleteRequest,
    MFARegisterRequest, MFAVerifyRequest, MFAValidateRequest, 
    MFAVerifyResponse, MFARegisterResponse, PasswordChangeRequest,
)


# --- Azure Table Connection ---
users_client = connect_to_table(USERS_TABLE_NAME, SAS_TOKEN, ENDPOINT)


# --- In-Memory Storage for Pending MFA Secrets ---
pending_mfa_secrets = {}  # {email: encrypted_secret}


# --- FastAPI App ---
app = FastAPI(
    title="Auth Demo", description="Authenticatie & User Management", version="1.0"
)


# set the oauth scema 
oauth2_scheme = HTTPBearer()


def user_exists(email: str) -> bool:
    return entity_exists(users_client, USERS_TABLE_NAME, email)


@app.get("/")
def read_root():
    return {"message": "Welcome to the Auth API"}


@app.get("/favicon.ico")
def favicon():
    return {"message": "No favicon available"}


@app.post("/users/", status_code=201)
def register_user(user: UserCreate):
    email = user.email.lower()
    password = user.password

    if entity_exists(users_client, USERS_TABLE_NAME, email):
        raise HTTPException(status_code=400, detail="This email is already in use.")

    try:
        password_hash = b64e(bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()))
        insert_entity(users_client, USERS_TABLE_NAME, email, password_hash=password_hash)
        return {"message": "User successfully created."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating user: {e}")

@app.post(
    "/users/{email}/mfa/register",
    response_model=MFARegisterResponse,
    summary="Register MFA for a user"
)    
def mfa_register(email: str, data: MFARegisterRequest, credentials: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    email = email.lower()
    token = credentials.credentials
    try:
        token_data = decode_jwt_token(token)
        if token_data.get("email") != email:
            raise HTTPException(status_code=403, detail="Can only register MFA for your own account")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Verify the password and get user entity
    is_valid, user_entity = verify_user_password_with_entity(email, data.password, users_client, USERS_TABLE_NAME)
    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid password")

    # Check user exists (should be guaranteed by verify_user_password_with_entity)
    if not user_entity:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if MFA is already enabled (check for any totp_secret field)
    if user_entity.get("totp_secret"):
        raise HTTPException(status_code=400, detail="MFA is already enabled for this user")

    # If MFA setup is already in progress, just start over (clear previous attempt)
    pending_mfa_secrets.pop(email, None)

    # Generate TOTP secret and store it temporarily (in-memory, encrypted)
    secret = generate_totp_secret()
    encrypted_secret = encrypt_totp_secret_with_password(secret, data.password, email)
    pending_mfa_secrets[email] = encrypted_secret  # Store in memory
    
    # Generate QR code for authenticator apps (but don't return the secret)
    qr_b64, uri = generate_qr_base64(secret, email, issuer="MyAuthApp")
    return MFARegisterResponse(qr_base64=qr_b64, provisioning_uri=uri)


@app.post(
    "/users/{email}/mfa/verify",
    response_model=MFAVerifyResponse,
    summary="Verify MFA code"
)
def mfa_verify(email: str, data: MFAVerifyRequest, credentials: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    email = email.lower()
    token = credentials.credentials
    try:
        token_data = decode_jwt_token(token)
        if token_data.get("email") != email:
            raise HTTPException(status_code=403, detail="Can only verify MFA for your own account")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Verify the password and get user entity
    is_valid, user_entity = verify_user_password_with_entity(email, data.password, users_client, USERS_TABLE_NAME)
    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid password")

    if not user_entity:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Clear any existing pending MFA setup
    pending_mfa_secrets.pop(email, None)
    
    # Check if MFA is already enabled
    if user_entity.get("totp_secret"):
        raise HTTPException(status_code=400, detail="MFA is already enabled for this user")
    
    # Verify the TOTP code with the provided secret
    if not verify_totp_code(data.secret, data.code):
        raise HTTPException(status_code=401, detail="Invalid MFA code")
        
    # Code is valid! Encrypt and store permanently
    encrypted_secret = encrypt_totp_secret_with_password(data.secret, data.password, email)
    update_entity(users_client, user_entity, totp_secret=encrypted_secret)

    return MFAVerifyResponse(message="MFA has been successfully enabled for your account")


@app.post(
    "/users/{email}/mfa/validate",
    response_model=MFAVerifyResponse,
    summary="Validate MFA code for existing MFA-enabled user"
)
def mfa_validate(email: str, data: MFAValidateRequest, credentials: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    """
    Validate MFA code for a user who already has MFA enabled.
    Requires password to decrypt the stored TOTP secret.
    """
    email = email.lower()
    token = credentials.credentials
    try:
        token_data = decode_jwt_token(token)
        if token_data.get("email") != email:
            raise HTTPException(status_code=403, detail="Can only validate MFA for your own account")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Verify the password and get user entity
    is_valid, user_entity = verify_user_password_with_entity(email, data.password, users_client, USERS_TABLE_NAME)
    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid password")

    if not user_entity:
        raise HTTPException(status_code=404, detail="User not found")
        
    encrypted_secret = user_entity.get("totp_secret")
    if not encrypted_secret:
        raise HTTPException(status_code=400, detail="MFA not enabled for this user")

    try:
        # Decrypt the stored secret using the user's password
        stored_secret = decrypt_totp_secret_with_password(encrypted_secret, data.password, email)
    except Exception:
        raise HTTPException(status_code=500, detail="Error decrypting MFA secret")

    if not verify_totp_code(stored_secret, data.code):
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    return MFAVerifyResponse(message="MFA code validated successfully")


@app.get(
    "/users/{email}/mfa/status",
    summary="Check if MFA is enabled for a user"
)
def mfa_status(email: str, credentials: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    """
    Check if MFA is enabled for a user.
    """
    email = email.lower()
    token = credentials.credentials
    try:
        token_data = decode_jwt_token(token)
        if token_data.get("email") != email:
            raise HTTPException(status_code=403, detail="Can only check MFA status for your own account")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_entity = get_entity(users_client, USERS_TABLE_NAME, email)
    if not user_entity:
        raise HTTPException(status_code=404, detail="User not found")
        
    mfa_enabled = bool(user_entity.get("totp_secret"))
    return {"mfa_enabled": mfa_enabled}


@app.delete("/users/{email}/mfa", summary="Disable MFA for a user")
def mfa_disable(email: str, data: UserDeleteRequest, credentials: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    """
    Disable MFA for a user. Removes TOTP secret from database.
    Use this for recovery if MFA is corrupted or user lost access.
    """
    email = email.lower()
    token = credentials.credentials
    try:
        token_data = decode_jwt_token(token)
        if token_data.get("email") != email:
            raise HTTPException(status_code=403, detail="Can only disable MFA for your own account")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Verify password and get user entity
    is_valid, user_entity = verify_user_password_with_entity(email, data.password, users_client, USERS_TABLE_NAME)
    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid password")

    if not user_entity:
        raise HTTPException(status_code=404, detail="User not found")

    if not user_entity.get("totp_secret"):
        raise HTTPException(status_code=400, detail="MFA is not enabled for this user")

    # Remove TOTP secret from database
    try:
        # Azure Table Storage: set to None to remove the field
        update_entity(users_client, user_entity, totp_secret=None)
        
        # Clear any pending MFA setup as well
        pending_mfa_secrets.pop(email, None)
        
        return {"message": "MFA has been disabled for your account"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to disable MFA: {e}")


@app.post("/users/{email}/change-password", summary="Change user password")
def change_password(email: str, data: PasswordChangeRequest, credentials: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    """
    Change user password. If user has MFA enabled, re-encrypt TOTP secret with new password.
    """
    email = email.lower()
    token = credentials.credentials
    try:
        token_data = decode_jwt_token(token)
        if token_data.get("email") != email:
            raise HTTPException(status_code=403, detail="Can only change password for your own account")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Get user entity
    user_entity = get_entity(users_client, USERS_TABLE_NAME, email)
    if not user_entity:
        raise HTTPException(status_code=404, detail="User not found")

    # Verify current password
    stored_hash = b64d(user_entity["password_hash"])
    if not bcrypt.checkpw(data.current_password.encode("utf-8"), stored_hash):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    # Create new password hash
    new_password_hash = b64e(bcrypt.hashpw(data.new_password.encode("utf-8"), bcrypt.gensalt()))

    # Handle MFA secret re-encryption if user has MFA enabled
    update_fields = {"password_hash": new_password_hash}
    
    encrypted_secret = user_entity.get("totp_secret")
    if encrypted_secret:
        try:
            # Decrypt with old password
            stored_secret = decrypt_totp_secret_with_password(encrypted_secret, data.current_password, email)
            # Re-encrypt with new password
            new_encrypted_secret = encrypt_totp_secret_with_password(stored_secret, data.new_password, email)
            update_fields["totp_secret"] = new_encrypted_secret
        except Exception:
            raise HTTPException(status_code=500, detail="Failed to re-encrypt MFA secret. Please contact support.")

    # Update user in database
    try:
        update_entity(users_client, user_entity, **update_fields)
        return {"message": "Password changed successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update password: {e}")


@app.delete("/users/{email}", status_code=204)
def delete_user(email: str, data: UserDeleteRequest, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    email = email.lower()
    # Get the token from the credentials
    token = credentials.credentials
    # Verify JWT token
    try:
        token_data = decode_jwt_token(token)
        if token_data.get("email") != email:
            raise HTTPException(status_code=403, detail="You can only delete your own account.")
    except Exception:
        raise HTTPException(status_code=401, detail="Not logged in or invalid token.")

    # Check if user exists
    entity = get_entity(users_client, USERS_TABLE_NAME, email)
    if not entity:
        raise HTTPException(status_code=404, detail="User not found.")

    # Verify if password is the
    stored_hash = b64d(entity["password_hash"])
    if not bcrypt.checkpw(data.password.encode("utf-8"), stored_hash):
        raise HTTPException(status_code=401, detail="Incorrect password.")

    # Delete user
    success = delete_entity(users_client, USERS_TABLE_NAME, email)
    if not success:
        raise HTTPException(status_code=500, detail="Error deleting user.")
    return 



@app.post("/login/", response_model=LoginResponse)
def login_user(user: UserLogin):
    email = user.email.lower()
    password = user.password
    mfa_code = user.code

    entity = get_entity(users_client, USERS_TABLE_NAME, email)
    if not entity:
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    stored_hash = b64d(entity["password_hash"])
    if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    # Check if MFA is enabled for this user
    encrypted_secret = entity.get("totp_secret")
    mfa_enabled = bool(encrypted_secret)
    
    if mfa_enabled:
        # MFA is enabled - require MFA code
        if not mfa_code:
            raise HTTPException(status_code=400, detail="MFA code required")
        
        # Validate MFA code
        try:
            stored_secret = decrypt_totp_secret_with_password(encrypted_secret, password, email)
            if not verify_totp_code(stored_secret, mfa_code):
                raise HTTPException(status_code=401, detail="Invalid MFA code")
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid MFA code")
    
    # Login successful - create tokens
    token_data = {"email": email}
    access_token = create_jwt_token(token_data, JWT_EXP_MINUTES)
    refresh_token = create_jwt_token(token_data, REFRESH_TOKEN_EXP_MINUTES)
    return LoginResponse(
        access_token=access_token, 
        refresh_token=refresh_token, 
        mfa_required=mfa_enabled
    )


@app.post("/refresh_token", summary="Refresh the JWT access token using the refresh token")
async def refresh_token_endpoint(data: RefreshRequest):
    try:
        # Decode the refresh token
        refresh_data = decode_jwt_token(data.refresh_token)

        # Ensure that email is present in the payload and exists in the user database
        email = refresh_data.get("email")
        if not email or not user_exists(email):
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        # Ensure the refresh token is still valid
        exp = refresh_data.get("exp")
        if not exp or datetime.now(timezone.utc) > datetime.fromtimestamp(exp, tz=timezone.utc):
            raise HTTPException(status_code=401, detail="Refresh token expired")

        # Create new tokens (remove exp and any other time-based fields)
        payload = {"email": email}

        # Create new access and refresh tokens
        new_access_token = create_jwt_token(payload, JWT_EXP_MINUTES)
        new_refresh_token = create_jwt_token(payload, REFRESH_TOKEN_EXP_MINUTES)

        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred during token refresh: {e}")

# --- Runnen voor lokaal testen ---
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
