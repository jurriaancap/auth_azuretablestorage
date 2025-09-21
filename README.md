# Authentication App

A secure authentication application using FastAPI, Azure Table Storage, and JWT tokens for user management.

## Features

- User registration with password hashing (bcrypt and unique salt per user)
- User login with JWT access and refresh tokens
- Secure token refresh endpoint
- User deletion (requires password and authentication)
- User data stored in Azure Table Storage
- Standardized database helper functions for all table operations
- Environment-based configuration (no secrets in code)

## Technologies Used

- Python 3.10+
- FastAPI
- Azure Table Storage
- PyJWT
- bcrypt

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/jurriaancap/auth_azuretablestorage
cd auth_azuretablestorage
```

### 2. Create an Azure Storage Account

You need an Azure Storage Account to use Azure Table Storage.  
Follow the official Microsoft Learn guide:  
[Create an Azure Storage account](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-create?tabs=azure-portal)

### 3. Set up environment variables

Create a `.env` file in the project root with the following variables:  
See `.env_example` for an example, customize to your needs.

```
JWT_SECRET=your_jwt_secret
JWT_ALGORITHM=HS256
JWT_EXP_MINUTES=15        # max 15 minutes
REFRESH_TOKEN_EXP_MINUTES=43200  # max 7 days
USERS_TABLE_NAME=Users
AZURE_TABLE_CONN_STRING=your_azure_table_sas_token
AZURE_TABLE_ENDPOINT=https://yourstorageaccount.table.core.windows.net/
```

**Never commit your `.env` file!**

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Run the application

```bash
uvicorn main:app --reload
```

Visit [http://localhost:8000/docs](http://localhost:8000/docs) for the interactive API documentation.

## API Endpoints

- **POST /users/**: Register a new user (email and password required)
- **POST /login/**: Login and receive JWT access and refresh tokens
- **POST /refresh_token**: Refresh your access token using a valid refresh token
- **DELETE /users/{email}**: Delete your user account (requires authentication and password confirmation)

## Security Notes

- Passwords are hashed with bcrypt and a unique salt per user (salt is stored in the hash).
- JWT secrets should be generated with high entropy (use `openssl rand -hex 64` for best practice).
- All authentication and sensitive operations require a valid JWT token.
- Database operations are standardized using helper functions for insert, get, delete, and existence checks.

## Configuration

- All secrets and connection strings are loaded from environment variables.
- See `.env.example` for a template.

## License

MIT License

## Contributing

Pull requests are welcome. For major changes, open an issue first to discuss your ideas.

## Contact

For questions or support, leave a message