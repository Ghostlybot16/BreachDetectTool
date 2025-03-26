# This file will handle:
# - Password Hashing and Verification
# - JWT Token Creation & Verification, Sign token using private key (RS256) & Validate token using public key
# - OAuth2 Tokens

import jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from .config import app_config

# Load RSA Private and Public keys 
with open(app_config.JWT_PRIVATE_KEY, "r") as f:
    PRIVATE_KEY = f.read()

with open(app_config.JWT_PUBLIC_KEY, "r") as f:
    PUBLIC_KEY = f.read()

# Retrieve JWT Algorithm and Token Expiration
ALGORITHM = app_config.JWT_ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = int(app_config.ACCESS_TOKEN_EXPIRE_MINUTES)

# Using bcrypt as password-hashing function for regular users 
pwd_context_user = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Using a stronger password-hashing function (argon2) for admins
pwd_context_admin = CryptContext(schemes=["argon2"], deprecated="auto")

# OAuth2 Bearer Token Setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Function to check is a user has the right role 
def check_role(required_role: str):
    """
    Middleware to check if the user has the required role. 
    - Extracts the role from the JWT token
    - Raised HTTP 403 Forbidden if the user does not have permission
    """
    def role_dependency(token: str = Depends(oauth2_scheme)):
        payload = verify_access_token(token)
        user_role = payload.get("role")
    
        if user_role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Missing permission to access this resource."
            )
        return payload 
    return role_dependency

# Function to restrict access to only the superadmin
def check_superadmin():
    """
    - Dependency to allow only the superadmin to access certain endpoints.
    - Extracts and verifies that the role in JWT token is 'super_admin'.
    """
    def role_dependency(token: str = Depends(oauth2_scheme)):
        
        payload = verify_access_token(token) # Verify the token
        
        if payload.get("role") != "super_admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only superadmin can access this resource."
            )
        return payload 
    return role_dependency

# -----------------------------------
# Password Hashing and Verification
# -----------------------------------

# Functions for password hashing & verification
def hash_password(password: str, role: str) -> str:
    """
    Hashes the password based on the user's role:
    - Admin passwords get hashed with Argon2 (stronger)
    - Regular user passwords get hashed with Bcrypt (fast and efficient)
    """
    if role == "admin":
        return pwd_context_admin.hash(password)
    return pwd_context_user.hash(password)

def verify_password(plain_password: str, hashed_password: str, role: str) -> bool:
    """
    Verified password against stored hash values 
    - Admin passwords are checked with Argon2
    - User passwords are checked with Bcrypt
    """
    if role in ["admin", "super_admin"]:
        return pwd_context_admin.verify(plain_password, hashed_password)
    return pwd_context_user.verify(plain_password, hashed_password)


# -----------------------------------
# JWT Token Functions (RS256)
# -----------------------------------

# Function to create JWT access tokens signed with RSA private key
def create_access_token(email: str, role: str, expires_delta: timedelta = None) -> str:
    """
    Generates a JWT token that includes:
    - User email
    - User role 
    - Expiry timestamp
    """
    to_encode = {"sub": email, "role": role}
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    
    return jwt.encode(to_encode, PRIVATE_KEY, algorithm=ALGORITHM)


# Function to VERIFY JWT TOKEN using the RSA public key
def verify_access_token(token: str) -> dict:
    try:
        # Ensure token is a string before decoding
        if not isinstance(token, str):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Token: Token must be a string"
            )
                
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Expired Token"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Token"
        )

# Extract and verify JWT token from requests
# Ensures protected routes only allow authenticated users
def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    return verify_access_token(token)