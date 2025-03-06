# This file will handle:
# - Password Hashing and Verification
# - JWT Token Creation & Verification, Sign token using private key (RS256) & Validate token using public key
# - OAuth2 Tokens

import jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from config import app_config

# Load RSA Private and Public keys 
with open(app_config.JWT_PRIVATE_KEY, "r") as f:
    PRIVATE_KEY = f.read()

with open(app_config.JWT_PUBLIC_KEY, "r") as f:
    PUBLIC_KEY = f.read()

# Retrieve JWT Algorithm and Token Expiration
ALGORITHM = app_config.JWT_ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = int(app_config.ACCESS_TOKEN_EXPIRE_MINUTES)

# Using bcrypt as password-hashing function
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 Bearer Token Setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# Functions for password hashing & verification
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)



# Function to CREATE JWT TOKENS using RS256
def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    
    return jwt.encode(to_encode, PRIVATE_KEY, algorithm=ALGORITHM)


# Function to VERIFY JWT TOKENS
def verify_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Expired Token")
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Token"
        )

# Extract and verify JWT token from requests
# Ensures protected routes only allow authenticated users
def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    return verify_access_token(token)