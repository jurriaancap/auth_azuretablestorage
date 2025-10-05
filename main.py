import bcrypt
from fastapi import FastAPI, HTTPException, Depends 
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timezone

## special import from my auth.helpers files
from auth.helpers import b64e, b64d, create_jwt_token, decode_jwt_token, encrypt_with_key, decrypt_with_key, derive_key_from_password
from auth.db_helpers import connect_to_table, entity_exists, insert_entity, get_entity, delete_entity, update_entity
from auth.mfa import generate_totp_secret, generate_qr_base64, verify_totp_code

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
    MFAVerifyResponse, MFARegisterResponse,
)


# --- Azure Table Connection ---
users_client = connect_to_table(USERS_TABLE_NAME, SAS_TOKEN, ENDPOINT)


# --- Helper Functions for TOTP Secret Encryption ---
def encrypt_totp_secret_with_password(secret: str, password: str, email: str) -> str:
    """Encrypt a TOTP secret using the user's password"""
    # Use email as salt (unique per user)
    salt = email.encode('utf-8')[:16].ljust(16, b'0')  # Ensure 16 bytes
    key = derive_key_from_password(password, salt)
    nonce, ciphertext, tag = encrypt_with_key(key, secret)
    # Store as "nonce:ciphertext:tag" format
    return f"{nonce}:{ciphertext}:{tag}"


def decrypt_totp_secret_with_password(encrypted_secret: str, password: str, email: str) -> str:
    """Decrypt a TOTP secret using the user's password"""
    try:
        # Check if it's encrypted (contains colons)
        if ":" not in encrypted_secret:
            # Probably an old unencrypted secret - return as is for backward compatibility
            return encrypted_secret
            
        nonce, ciphertext, tag = encrypted_secret.split(":")
        # Use email as salt (same as encryption)
        salt = email.encode('utf-8')[:16].ljust(16, b'0')  # Ensure 16 bytes
        key = derive_key_from_password(password, salt)
        return decrypt_with_key(key, nonce, ciphertext, tag)
    except Exception as e:
        raise ValueError(f"Failed to decrypt TOTP secret: {e}")


def verify_user_password(email: str, password: str) -> bool:
    """Verify a user's password against stored hash"""
    user_entity = get_entity(users_client, USERS_TABLE_NAME, email)
    if not user_entity:
        return False
    
    stored_hash = b64d(user_entity["password_hash"])
    return bcrypt.checkpw(password.encode("utf-8"), stored_hash)


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

    # Verify the password
    if not verify_user_password(email, data.password):
        raise HTTPException(status_code=401, detail="Invalid password")

    # Check user exists
    user_entity = get_entity(users_client, USERS_TABLE_NAME, email)
    if not user_entity:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if MFA is already enabled (check for any totp_secret field)
    if user_entity.get("totp_secret"):
        raise HTTPException(status_code=400, detail="MFA is already enabled for this user")

    # Check if MFA setup is already in progress
    if user_entity.get("totp_secret_pending"):
        raise HTTPException(status_code=400, detail="MFA setup already in progress. Please complete verification or start over.")

    # Generate TOTP secret and store it temporarily (encrypted)
    secret = generate_totp_secret()
    encrypted_secret = encrypt_totp_secret_with_password(secret, data.password, email)
    update_entity(users_client, user_entity, totp_secret_pending=encrypted_secret)
    
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

    # Verify the password
    if not verify_user_password(email, data.password):
        raise HTTPException(status_code=401, detail="Invalid password")

    user_entity = get_entity(users_client, USERS_TABLE_NAME, email)
    if not user_entity:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check if there's a pending MFA setup
    encrypted_pending_secret = user_entity.get("totp_secret_pending")
    if not encrypted_pending_secret:
        raise HTTPException(status_code=400, detail="No MFA setup in progress. Please register MFA first.")
    
    try:
        # Decrypt the pending secret using the user's password
        pending_secret = decrypt_totp_secret_with_password(encrypted_pending_secret, data.password, email)
    except Exception:
        raise HTTPException(status_code=500, detail="Error decrypting pending MFA secret")
    
    # Verify the TOTP code with the decrypted secret
    if not verify_totp_code(pending_secret, data.code):
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    # Code is valid! Move from pending to permanent and cleanup
    encrypted_secret = encrypt_totp_secret_with_password(pending_secret, data.password, email)
    update_entity(users_client, user_entity, totp_secret=encrypted_secret, totp_secret_pending=None)

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

    # Verify the password
    if not verify_user_password(email, data.password):
        raise HTTPException(status_code=401, detail="Invalid password")

    user_entity = get_entity(users_client, USERS_TABLE_NAME, email)
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


@app.delete(
    "/users/{email}/mfa/setup",
    summary="Cancel MFA setup in progress"
)
def mfa_cancel_setup(email: str, credentials: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    """
    Cancel MFA setup that's in progress (clears pending secret).
    """
    email = email.lower()
    token = credentials.credentials
    try:
        token_data = decode_jwt_token(token)
        if token_data.get("email") != email:
            raise HTTPException(status_code=403, detail="Can only cancel MFA setup for your own account")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_entity = get_entity(users_client, USERS_TABLE_NAME, email)
    if not user_entity:
        raise HTTPException(status_code=404, detail="User not found")
        
    if not user_entity.get("totp_secret_pending"):
        raise HTTPException(status_code=400, detail="No MFA setup in progress")
    
    # Clear the pending secret
    update_entity(users_client, user_entity, totp_secret_pending=None)
    return {"message": "MFA setup cancelled. You can start over by registering again."}

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

    entity = get_entity(users_client, USERS_TABLE_NAME, email)
    if not entity:
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    stored_hash = b64d(entity["password_hash"])
    if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token_data = {"email": email}
    access_token = create_jwt_token(token_data, JWT_EXP_MINUTES)
    refresh_token = create_jwt_token(token_data, REFRESH_TOKEN_EXP_MINUTES)
    return LoginResponse(access_token=access_token, refresh_token=refresh_token)


@app.post("/refresh_token", summary="Refresh the JWT access token using the refresh token")
async def refresh_token_endpoint(data: RefreshRequest):
    try:
        # Decode the refresh token
        refresh_data = decode_jwt_token(data.refresh_token)
        print(refresh_data)

        # Ensure that email is present in the payload and exists in the user database
        email = refresh_data.get("email")
        if not email or not user_exists(email):
            raise HTTPException(status_code=401, detail="Invalid refresh token")


        # Ensure the refresh token is still valid
        exp = refresh_data.get("exp")
        if not exp or datetime.now(timezone.utc) > datetime.fromtimestamp(exp, tz=timezone.utc):
            raise HTTPException(status_code=401, detail="Refresh token expired")

        # Reuse the contents of the old jwt token but remove 'exp' from payload if present, so new tokens get new expiry
        payload = {k: v for k, v in refresh_data.items() if k != "exp"}

        # Create new access and refresh tokens
        new_access_token = create_jwt_token(payload, JWT_EXP_MINUTES)
        new_refresh_token = create_jwt_token(payload, REFRESH_TOKEN_EXP_MINUTES)

        print(f"new {decode_jwt_token(new_access_token)}")

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
