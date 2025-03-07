# This file contains API endpoints for the FastAPI backend

import json
from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from database import get_db
from models import User
from auth import (
    hash_password, 
    verify_password, 
    create_access_token, 
    oauth2_scheme, 
    verify_access_token,
    check_role
)
from pydantic import BaseModel
from datetime import timedelta


router = APIRouter()


# Pydantic Schema for User Requests
class UserCreate(BaseModel):
    """Schema for user registratin and login requests"""
    email: str # User email (required)
    password: str # User password (required)
    role: str = "user"

class TokenResponse(BaseModel):
    """Schema for responses that return a JWT token"""
    access_token: str # JWT token string
    token_type: str # Token type (Bearer)



# ------------------------------
# User Registration Endpoint
# ------------------------------
@router.post("/register", response_model=TokenResponse)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    """
    Registers a new user in the database 
    - Hashes the password before storing 
    - Generates and returns a RS256 JWT Token
    """
    # Query the database to check if the email is already registered
    query_result = await db.execute(select(User).where(User.email == user.email))
    existing_user = query_result.scalars().first() 
    print(f"Checking for existing user: {user.email} -> {existing_user}")
    
    if existing_user: 
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Ensure only an authenticated admins can create new admins 
    if user.role == "admin":
        current_user = verify_access_token(oauth2_scheme)
        
        # Query the database for the current user's role
        query_result = await db.execute(select(User).where(User.email == current_user["sub"]))
        current_user_db = query_result.scalars().first()
        
        # If user does not exist in the database or the role isn't admin then return 403 Forbidden error message
        if not current_user_db or current_user_db.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admins can create new admins"
            )
    # Hash users password for secure storage
    # user.role determines which function to use based on user or admin account
    hashed_password = hash_password(user.password, user.role)  
    
    # New user gets added to the database 
    new_user = User(email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    await db.commit() # Save user to the database
    await db.refresh(new_user) # Refresh to get the latest state
    
    # Generate a JWT access token for the new user 
    access_token = create_access_token(new_user.email, new_user.role)
    
    # Return the token so the user is logged in immediately 
    return Response(
        content=json.dumps({
            "access_token": access_token,
            "token_type": "bearer"
            }),
        status_code=status.HTTP_201_CREATED,
        media_type="application/json"
    )



# ------------------------------
# User Login Endpoint
# ------------------------------
@router.post("/login", response_model=TokenResponse)
async def login(user: UserCreate, db: AsyncSession = Depends(get_db)):
    """
    Authenticates a user
    - Checks if the user exists and verified the password 
    - Generated and returns a JWT token
    """
    # Query the DB looking for the user's email
    query_result = await db.execute(select(User).where(User.email == user.email))
    db_user = query_result.scalars().first()
    
    # If user is NOT FOUND or INCORRECT PASSWORD, return an error 
    if not db_user or not verify_password(user.password, db_user.hashed_password, db_user.role):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid credentials"
        )
    
    # Generate a JWT access token for the authenticated user 
    access_token = create_access_token(db_user.email, db_user.role)
    
    # Return the token to login
    return Response(
        content=json.dumps({
            "access_token": access_token,
            "role": db_user.role,
            "token_type": "bearer"
        }),
        status_code=status.HTTP_200_OK,
        media_type="application/json"
    )


# ------------------------------
# Protected Route (Requires JWT Token)
# ------------------------------
@router.get("/protected")
async def protected_route(token: str = Depends(oauth2_scheme)):
    """
    Protected route that requires a valid JWT token
    - Extracts and verifies the JWT
    - Returns a success message if the token is valid 
    """
    
    # Verify the JWT token to extract user information 
    payload = verify_access_token(token)
    
    return Response(
        content=json.dumps({
            "message": "Access Granted",
            "user": payload["sub"]
        }),
        status_code=status.HTTP_200_OK,
        media_type="application/json"
    )

@router.get("/admin-only", dependencies=[Depends(check_role("admin"))])
async def admin_dashboard():
    return {"message": "Welcome, Admin! You have full access"}

@router.get("/")
async def home():
    return {"message": "Welcome to the Breach Detection API"}

@router.get("/health")
async def health_check():
    return {"status": "OK"}
