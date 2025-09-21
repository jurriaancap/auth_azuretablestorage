import bcrypt
from azure.data.tables import TableEntity
from fastapi import FastAPI, HTTPException, Request, Depends 
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from pydantic import BaseModel, EmailStr
from datetime import datetime, timezone

from auth.helpers import b64e, b64d, create_jwt_token, decode_jwt_token

from auth.db_helpers import connect_to_table, set_entity, entity_exists, insert_entity, get_entity, delete_entity

from auth.config import (
    ## import the variables from config.py 
    JWT_EXP_MINUTES,
    REFRESH_TOKEN_EXP_MINUTES, 
    USERS_TABLE_NAME,
    SAS_TOKEN,
    ENDPOINT,

)

## from auth/classes.py import the classes
from auth.classes import UserCreate, UserLogin, RefreshRequest, LoginResponse ,UserDeleteRequest


# --- Azure Table Connection ---
users_client = connect_to_table(USERS_TABLE_NAME, SAS_TOKEN, ENDPOINT)




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
