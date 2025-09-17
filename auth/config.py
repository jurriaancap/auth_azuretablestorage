from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# --- Configuratie ---
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
SAS_TOKEN = os.getenv("AZURE_TABLE_CONN_STRING")
ENDPOINT = os.getenv("AZURE_TABLE_ENDPOINT")
USERS_TABLE_NAME = os.getenv("USERS_TABLE_NAME", "Users")
JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", "15"))
REFRESH_TOKEN_EXP_MINUTES = int(os.getenv("REFRESH_TOKEN_EXP_MINUTES", "43200"))  # 30 dagen

# Check vereiste env vars
missing = []
if not JWT_SECRET:
    missing.append("JWT_SECRET")
if not SAS_TOKEN:
    missing.append("AZURE_TABLE_CONN_STRING")
if not ENDPOINT:
    missing.append("AZURE_TABLE_ENDPOINT")
if missing:
    print(f"Missing environment variables: {', '.join(missing)}")
    raise RuntimeError(
        f"Required environment variable(s) missing: {', '.join(missing)}"
    )
