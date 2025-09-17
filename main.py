import bcrypt
from azure.data.tables import TableEntity
from fastapi import FastAPI, HTTPException, Request 
from pydantic import BaseModel, EmailStr
from datetime import datetime, timezone

from auth.helpers import b64e, b64d, create_jwt_token, decode_jwt_token

from auth.db_helpers import connect_to_table

from auth.config import (
    ## import the variables from config.py 
    JWT_EXP_MINUTES,
    REFRESH_TOKEN_EXP_MINUTES, 
    USERS_TABLE_NAME,
    SAS_TOKEN,
    ENDPOINT,

)

## from auth/classes.py import the classes
from auth.classes import UserCreate, UserLogin, RefreshRequest, LoginResponse 


# --- Azure Table Connection ---
users_client = connect_to_table(USERS_TABLE_NAME, SAS_TOKEN, ENDPOINT)




# --- FastAPI App ---
app = FastAPI(
    title="Auth Demo", description="Authenticatie & User Management", version="1.0"
)


def user_exists(email: str) -> bool:
    try:
        users_client.get_entity(partition_key=USERS_TABLE_NAME, row_key=email)
        return True
    except Exception:
        return False


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

    if user_exists(email):
        raise HTTPException(status_code=400, detail="Deze email is al in gebruik.")

    try:
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        entity = TableEntity(
            PartitionKey=USERS_TABLE_NAME,
            RowKey=email,
            password_hash=b64e(password_hash),
        )
        users_client.upsert_entity(entity=entity)
        return {"message": "Gebruiker succesvol aangemaakt."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fout bij aanmaken gebruiker: {e}")


@app.post("/login/", response_model=LoginResponse)
def login_user(user: UserLogin):
    email = user.email.lower()
    password = user.password

    try:
        entity = users_client.get_entity(partition_key=USERS_TABLE_NAME, row_key=email)
        stored_hash = b64d(entity["password_hash"])
        if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
            raise HTTPException(
                status_code=401, detail="Ongeldige gebruikersnaam of wachtwoord."
            )
        # JWT token aanmaken
        token_data = {"email": email}
        access_token = create_jwt_token(token_data, JWT_EXP_MINUTES)
        refresh_token = create_jwt_token(token_data, REFRESH_TOKEN_EXP_MINUTES)
        return LoginResponse(access_token=access_token, refresh_token=refresh_token)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=401, detail="Ongeldige gebruikersnaam of wachtwoord."
        )

@app.post("/refresh_token", summary="Refresh the JWT access token using the refresh token")
async def refresh_token_endpoint(data: RefreshRequest):
    try:
        # Decode the refresh token
        refresh_data = decode_jwt_token(data.refresh_token)
        print(refresh_data)

        #ensure that email is present in the payload and exists in the user database
        email = refresh_data.get("email")
        if not email or not user_exists(email):
            raise HTTPException(status_code=401, detail="Invalid refresh token")


        # Ensure the refresh token is still valid
        exp = refresh_data.get("exp")
        if not exp or datetime.now(timezone.utc) > datetime.fromtimestamp(exp, tz=timezone.utc):
            raise HTTPException(status_code=401, detail="Refresh token expired")

        # reuse the contents of the old jwt token but remove 'exp' from payload if present, so new tokens get new expiry
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
