# Authentication App with Multi-Factor Authentication

A production-ready authentication application featuring Multi-Factor Authentication (MFA), built with FastAPI, Azure Table Storage, and comprehensive security features.

## Features

### Core Authentication
- User registration with password hashing (bcrypt with unique salts)
- JWT access and refresh tokens with configurable expiration
- Secure token refresh endpoint
- Password change with automatic MFA re-encryption
- User account deletion with proper authentication

### Multi-Factor Authentication (MFA)
- TOTP-based MFA using industry-standard authenticator apps (Google Authenticator, Authy, etc.)
- QR Code generation for easy authenticator setup
- Password-based encryption of TOTP secrets (unique per user)
- Seamless MFA integration with login flow
- MFA management: Enable, disable, and validate MFA codes
- Automatic re-encryption during password changes (MFA stays functional)
- Recovery mechanisms for corrupted or lost MFA access

### Architecture & Security
- Azure Table Storage for scalable user data persistence
- Per-user encryption with email-based salts for TOTP secrets
- AES-GCM encryption with PBKDF2 key derivation (100,000 iterations)
- Stateless MFA - no server-side storage needed for login
- Database optimization - reduced redundant calls with efficient patterns
- Comprehensive error handling and validation

### Testing & Quality
- 35 comprehensive tests covering all functionality
- Unit tests for individual functions and utilities
- Integration tests for complete user workflows
- API endpoint tests with proper mocking
- 59% code coverage with detailed reports
- Professional test structure following Python best practices

## Technologies Used

- **Backend**: Python 3.12+, FastAPI
- **Database**: Azure Table Storage
- **Authentication**: PyJWT, bcrypt
- **MFA**: pyotp (TOTP), qrcode generation
- **Encryption**: PyCryptodome (AES-GCM)
- **Testing**: pytest, coverage, httpx
- **Environment**: uv for dependency management

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/jurriaancap/auth_azuretablestorage.git
cd auth_azuretablestorage
```

### 2. Set Up Python Environment

```bash
# Install uv (modern Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create virtual environment and install dependencies
uv sync

# Activate environment
source .venv/bin/activate
```

### 3. Configure Azure Storage

Create an Azure Storage Account and Table Storage:
- Follow [Microsoft's official guide](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-create?tabs=azure-portal)
- Note your storage account name and connection details

### 4. Environment Configuration

Create a `.env` file (see `.env_example` for template):

```env
# JWT Configuration
JWT_SECRET=your_super_secure_jwt_secret_here
JWT_ALGORITHM=HS256
JWT_EXP_MINUTES=15
REFRESH_TOKEN_EXP_MINUTES=10080

# Database Configuration  
USERS_TABLE_NAME=Users
SAS_TOKEN=your_azure_sas_token
ENDPOINT=https://yourstorageaccount.table.core.windows.net/
```

**Security Note**: Generate a strong JWT secret:
```bash
openssl rand -hex 64
```

### 5. Run the Application

```bash
# Development server with auto-reload
uvicorn main:app --reload

# Or using the Python module
python main.py
```

Visit **[http://localhost:8000/docs](http://localhost:8000/docs)** for interactive API documentation.

## API Endpoints

### User Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/users/` | Register new user |
| `POST` | `/login/` | Login (supports MFA) |
| `POST` | `/refresh_token` | Refresh access token |
| `POST` | `/users/{email}/change-password` | Change password + re-encrypt MFA |
| `DELETE` | `/users/{email}` | Delete user account |

### Multi-Factor Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/users/{email}/mfa/register` | Start MFA setup (get QR code) |
| `POST` | `/users/{email}/mfa/verify` | Complete MFA setup |
| `POST` | `/users/{email}/mfa/validate` | Test MFA code |
| `GET` | `/users/{email}/mfa/status` | Check if MFA is enabled |
| `DELETE` | `/users/{email}/mfa` | Disable MFA (recovery) |

## MFA Setup Flow

### For Users:
1. **Register account** with email/password
2. **Login** to get JWT token
3. **Start MFA setup**: `POST /users/{email}/mfa/register`
4. **Scan QR code** with authenticator app (Google Authenticator, Authy, etc.)
5. **Complete setup**: `POST /users/{email}/mfa/verify` with first TOTP code
6. **Future logins**: Include MFA code in login request

### Example Login with MFA:
```json
POST /login/
{
  "email": "user@example.com",
  "password": "securepassword",
  "code": "123456"
}
```

## Testing

### Run Tests

```bash
# All tests
./run_tests.sh all

# Specific categories
./run_tests.sh unit        # Unit tests only
./run_tests.sh endpoints   # API endpoint tests
./run_tests.sh integration # End-to-end tests

# With coverage report
./run_tests.sh coverage
```

### Test Coverage
- **35 tests** covering all major functionality
- **Unit tests**: Base64, encryption, TOTP, password verification
- **API tests**: All endpoints with success/failure scenarios  
- **Integration tests**: Complete user journeys
- **Coverage**: 59% overall (view detailed report in `htmlcov/index.html`)

## Project Structure

```
authentication_app/
├── main.py                 # FastAPI application
├── auth/                   # Authentication modules
│   ├── classes.py         # Pydantic models
│   ├── config.py          # Configuration management
│   ├── db_helpers.py      # Azure Table Storage operations
│   ├── helpers.py         # Utility functions
│   └── mfa.py            # MFA/TOTP functionality
├── tests/                 # Comprehensive test suite
│   ├── conftest.py       # Shared test fixtures
│   ├── test_main.py      # API endpoint tests
│   ├── test_auth_*.py    # Unit tests
│   └── test_integration.py # End-to-end tests
├── run_tests.sh          # Test runner script
├── pytest.ini           # Test configuration
└── htmlcov/             # Coverage reports (gitignored)
```

## Security Features

### Authentication Security
- **bcrypt hashing** with unique salts per user
- **JWT tokens** with configurable expiration
- **Refresh token rotation** for enhanced security
- **Password verification** required for sensitive operations

### MFA Security 
- **TOTP (Time-based One-Time Password)** industry standard
- **AES-GCM encryption** for TOTP secret storage
- **PBKDF2 key derivation** (100,000 iterations)
- **Per-user encryption keys** using email-based salts
- **Forward secrecy** - password changes invalidate old encrypted data

### Database Security
- **Azure Table Storage** with SAS token authentication
- **No plaintext secrets** stored in database
- **Atomic updates** for critical operations
- **Proper error handling** without information leakage

## Configuration

### Environment Variables
All configuration through environment variables (see `.env_example`):

```env
# Required
JWT_SECRET=                # Strong random secret
SAS_TOKEN=                # Azure Table Storage SAS token
ENDPOINT=                 # Azure Table Storage endpoint

# Optional (with defaults)
JWT_ALGORITHM=HS256
JWT_EXP_MINUTES=15
REFRESH_TOKEN_EXP_MINUTES=10080
USERS_TABLE_NAME=Users
```

### Deployment Considerations
- **Never commit `.env` files**
- **Use strong JWT secrets** (64+ random bytes)
- **Configure appropriate token expiration**
- **Monitor Azure storage costs**
- **Set up proper logging in production**

## Development

### Adding New Features
1. **Write tests first** (TDD approach)
2. **Follow existing patterns** in the codebase
3. **Update documentation** 
4. **Run full test suite**: `./run_tests.sh all`
5. **Check coverage**: `./run_tests.sh coverage`

### Code Quality
- **Type hints** throughout codebase
- **Pydantic models** for data validation
- **Comprehensive error handling**
- **Clean separation of concerns**
- **Professional test coverage**

## Production Readiness

This application includes:
- Production-grade security (MFA, encryption, proper auth)
- Comprehensive testing (35 tests, multiple categories)
- Scalable architecture (Azure cloud storage)
- Proper error handling and validation
- Documentation and code organization
- Monitoring-ready (structured logging, health checks)

## Contributing

1. **Fork the repository**
2. **Create feature branch**: `git checkout -b feature-name`
3. **Write tests** for new functionality
4. **Ensure tests pass**: `./run_tests.sh all`
5. **Submit pull request**

For major changes, please open an issue first to discuss your ideas.

## License

MIT License - see LICENSE file for details.

## Support

For questions, issues, or feature requests:
- **Open an issue** on GitHub
- **Check the documentation** in `/docs`
- **Review test examples** in `/tests`

---

**Built with modern Python practices using FastAPI and Azure.**