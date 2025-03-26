# This file contains API endpoints for the FastAPI backend

import json, html, re, hashlib, requests, random, string, os, tempfile
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from fastapi.responses import FileResponse
from sqlalchemy import update
from .limiter import limiter
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from .database import get_db
from .models import User, BreachCheckHistory, GeneratedPassword
from .auth import (
    hash_password, 
    verify_password, 
    create_access_token, 
    oauth2_scheme, 
    verify_access_token,
    check_role,
    check_superadmin
)
from pydantic import BaseModel, EmailStr, field_validator
from datetime import timedelta
from typing import Optional


router = APIRouter()


# Pydantic Schema for User Requests
class UserCreate(BaseModel):
    """Schema for user registratin and login requests"""
    email: EmailStr # Ensures valid email format
    password: str 
    role: str = "user"

    # Role validation to prevent unauthorized role escalation
    @field_validator("role")
    @classmethod
    def validate_role(cls, value):
        allowed_roles = {"user", "admin"}
        if value.lower() not in allowed_roles:
            raise ValueError("Invalid role. Must be 'user' or 'admin'.")
        
        # Prevent non-superadmins (admins) from setting their role to admin
        if value.lower() == "admin":
            raise ValueError("Admins can only be crerated by the Super Admin.")
        return value.lower()
    
    
    # Password validation 
    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        """ Custom password validation for strong security"""
        if len(value) < 12: # Enforce minimum 12 chararacters
            raise ValueError("Password must be at least 12 characters long.")
        if not re.search(r"[A-Z]", value): # At least one UPPERCASE letter
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", value): # At least one LOWERCASE letter
            raise ValueError("Password must contain at least one lowercase letter.")
        if not re.search(r"\d", value): # At least one digit 
            raise ValueError("Password must contain at least one number.")
        if not re.search(r"[!@#$%^&*()_\-+=]", value): # At least one special character
            raise ValueError("Password must contain at least one special character (!@#$%^&*()_-+=).")
        return value
    
class TokenResponse(BaseModel):
    """Schema for responses that return a JWT token"""
    access_token: str # JWT token string
    token_type: str # Token type (Bearer)

class GeneratePasswordRequest(BaseModel):
    name: str 
    
    @field_validator("name")
    @classmethod
    def validate_name(cls, value):
        if not value.strip():
            raise ValueError("Password name cannot be empty.")
        return value.strip()

class StoreGeneratedPasswordRequest(BaseModel):
    """Schema for storing generated passwords"""
    name: str
    
    @field_validator("name")
    @classmethod
    def validate_name(cls, value):
        if not value.strip():
            raise ValueError("Password name cannot be empty.")
        return value.strip()

# Used to check user/weak password by users
class PasswordCheckRequest(BaseModel):
    password: str
    label: Optional[str] = None

# Used to reset admin password 
class PasswordResetRequest(BaseModel):
    email: str
    new_password: str

# ------------------------------
# User Registration Endpoint
# ------------------------------
@router.post("/register", response_model=TokenResponse)
@limiter.limit("5/minute") # Limit to 5 requests per minute per IP 
async def register(
    request: Request, 
    user: UserCreate, 
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme) # Token dependency (for admin verification)
    ):
    """
    Registers a new user in the database 
    - Normal users can register freely
    - Admin accounts can only be created by the Super admin
    - Hashes the password before storing 
    - Generates and returns a RS256 JWT Token after successful registration
    """
        
    # Query the database to check if the email is already registered
    query_result = await db.execute(select(User).where(User.email == user.email))
    existing_user = query_result.scalars().first() 
    
    if existing_user: 
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Ensure only an authenticated admins can create new admins and prevent normal users from creating admin accounts
    if user.role.lower() == "admin":
        
        # Authenticate the user (must be an admin to create new admins)
        current_user = verify_access_token(token) # Verify the token
        
        # Query the database for the current user's role
        query_result = await db.execute(select(User).where(User.email == current_user["sub"]))
        current_user_db = query_result.scalars().first()
        
        # If user does not exist in the database or the role isn't admin then return 403 Forbidden error message
        if not current_user_db or current_user_db.role != "super_admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the super admin can create new admin accounts."
            )
            
    # Hash users password for secure storage
    # user.role determines which function to use based on user or admin account
    hashed_password = hash_password(user.password, user.role)  
    
    # New user gets added to the database 
    new_user = User(email=user.email, hashed_password=hashed_password, role=user.role)
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
@limiter.limit("10/minute") # Limit to 10 logins per minute per IP
async def login(
    request: Request, 
    user: UserCreate, 
    db: AsyncSession = Depends(get_db)
    ):
    """
    Authenticates a user
    - Checks if the user exists and verified the password 
    - Generated and returns a JWT token
    """
    
    # Escape user input to prevent JSON injection
    user.email = html.escape(user.email)
    
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
# New Admin Creation Route (Only accessible by Super Admin)
# ------------------------------
@router.post("/create-admin", response_model=TokenResponse,dependencies=[Depends(check_superadmin())])
@limiter.limit("3/minute")
async def create_admin(
    request: Request,
    user: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    - Allows a superadmin to create new admin accounts
    - Validates role, checks for duplicates and stores a securely hashed admin password
    """
    
    # Force role to "admin" regardless of input 
    user.role = "admin"
    
    # Check if the email already exists in the database 
    query_result = await db.execute(select(User).where(User.email == user.email))
    existing_user = query_result.scalars().first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already exists."
        )
    
    # Hash teh admin password using argon2
    hashed_password = hash_password(user.password, user.role)
    
    # Store the new admin in the database
    new_user = User(email=user.email, hashed_password=hashed_password, role=user.role)
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    
    # Generate JWT token for the new admin
    access_token = create_access_token(new_user.email, new_user.role)
    
    return Response(
        content=json.dumps({
            "access_token": access_token,
            "token_type": "bearer"
        }),
        status_code=status.HTTP_201_CREATED,
        media_type="application/json"
    )

# ------------------------------
# Protected Route (Requires JWT Token)
# ------------------------------
@router.get("/protected")
@limiter.limit("15/minute") # Limit to 15 requests per minute per IP
async def protected_route(
    request: Request, 
    token: str = Depends(oauth2_scheme)
    ):
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
@limiter.limit("5/minute") # Limit to 5 requests per minute per IP
async def admin_dashboard(request: Request):
    return {"message": "Welcome, Admin! You have full access"}




        
    

# ------------------------------
# Check Password Breach With HIBP API Route
# ------------------------------
@router.post("/check-password-breach")
async def check_password_breach(
    request: Request,
    payload: PasswordCheckRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme)
):
    """
    Checks if a password has been compromised using the Have I Been Pawned API.
    
    - Hashes the password with SHA-1
    - Sends the first 5 characters of the hash to HIBP
    - Retrieves the response and checks if the full hash exists in the breached dataset.
    
    Returns: 
        JSON response with breach details.
    """
    password = payload.password
    
    # Verify User Authentication 
    user = verify_access_token(token) 
    if not user: 
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authentication"
        )
    
    # Fetch user from DB to get user.id
    query_result = await db.execute(select(User).where(User.email == user["sub"]))
    user_db = query_result.scalars().first()
    
    if not user_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User was not found in database."
        )
    
    # Verify password
    if not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password section cannot be empty."
        )
    
    # Hash the password using SHA-1
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    hash_prefix = sha1_hash[:5]
    hash_suffix = sha1_hash[5:]
    
    # HIBP API URL 
    hibp_url = f"https://api.pwnedpasswords.com/range/{hash_prefix}"
    
    
    try:
        response = requests.get(hibp_url)
        response.raise_for_status()
    except requests.RequestException as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Error reaching HIBP API: {str(e)}"
        )
    
    # Parse the response and check for the hash suffix 
    hashes = (line.split(":") for line in response.text.splitlines())
    breach_count = 0
    for h, count in hashes:
        if h == hash_suffix:
            breach_count = int(count)
            break
    
    # Prepare response 
    breach_status = "Breached" if breach_count > 0 else "Not Breached"
    
    # Log the breach check to the database 
    new_entry = BreachCheckHistory(
        user_id=user_db.id,
        email_checked=user["sub"],
        breached="Breached" if breach_status == "Breached" else "Not Breached",
        label=payload.label
    )
    
    db.add(new_entry)
    await db.commit()
    
    return {
        "status": breach_status,
        "breach_count": breach_count
    }

# ------------------------------
# Users can view previously checked passwords
# ------------------------------
@router.get("/password-check-history")
@limiter.limit("5/minute")
async def get_breach_history(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme)
):
    """
    - Allows users to retrieve their own password history
    """
    
    # Verify User Authentication 
    user = verify_access_token(token)
    
    # Query breach history for this user 
    query_result = await db.execute(select(User).where(User.email == user["sub"]))
    user_db = query_result.scalars().first()
    
    if not user_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    
    userID = await db.execute(
        select(BreachCheckHistory).where(BreachCheckHistory.user_id == user_db.id)
    )
    breach_history = userID.scalars().all()
    
    # Return history
    return {
        "history": [
            {
                "email_checked": record.email_checked,
                "breached": record.breached,
                "label": record.label,
                "check_time": record.check_time
            }
            for record in breach_history
        ]
    }




def generate_strong_password(length: int = 16) -> str:
    """ Generate a strong random password with:
    - At least one uppercase letter
    - At lesat one lowercase letter 
    - At least one digit 
    - At least one special character
    """
    
    if length < 12:
        raise ValueError("Password length must be at least 12 characters.")
    
    # Ensure at least one character from each category 
    uppercase = random.choice(string.ascii_uppercase)
    lowercase = random.choice(string.ascii_lowercase)
    digit = random.choice(string.digits)
    special = random.choice("!@#$%^&*()_+-=[]{}|;:,.<>?")
    
    # Fill the rest of the password with random characters 
    remaining_length = length - 4 
    remaining_chars = random.choices(
        string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?",
        k=remaining_length
    )
    
    # Combine and shuffle to make the password unpredictable 
    password_list = list(uppercase + lowercase + digit + special + ''.join(remaining_chars))
    random.shuffle(password_list)
    return ''.join(password_list)


# ------------------------------
# Storing Generated Passwords for User
# ------------------------------
@router.post("/store-generated-password")
@limiter.limit("5/minute")
async def store_generated_password(
    request: Request,
    password_request: StoreGeneratedPasswordRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme)
):
    """
    - Generates and stores a strong 16 character long password in the database for the authenticated user
    """
    
    # Verify user authentication
    user = verify_access_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authentication."
        )
    
    # Fetch the user from the database 
    query_result = await db.execute(select(User).where(User.email == user["sub"]))
    user_db = query_result.scalars().first()
    
    if not user_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    
    # Generate a strong password 
    generated_password = generate_strong_password()
    
    # Store the password in the database 
    new_password_entry = GeneratedPassword(
        user_id=user_db.id,
        name=password_request.name,
        password=generated_password
    )
    
    db.add(new_password_entry)
    await db.commit()
    await db.refresh(new_password_entry)
    
    # Return the generated password and name 
    return {
        "message": "Password stored successfully.",
        "name": new_password_entry.name,
        "password": new_password_entry.password,
        "created_at": new_password_entry.created_at
    }

# ------------------------------
# Retrieve Stored Passwords for User
# ------------------------------
@router.get("/get-stored-passwords")
@limiter.limit("5/minute")
async def get_stored_passwords(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme)
):
    """
    - Retrieves all stored passwords for the authenticated user 
    - Does NOT return the actual password for security reasons 
    """
    
    # Verify user authentication 
    user = verify_access_token(token)
    if not user: 
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authentication."
        )
    
    query_result = await db.execute(select(User).where(User.email == user["sub"]))
    user_db = query_result.scalars().first()
    
    if not user_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    
    password_result = await db.execute(
        select(GeneratedPassword).where(GeneratedPassword.user_id == user_db.id)
        )
    stored_passwords = password_result.scalars().all()
    
    if not stored_passwords:
        return {"message": "No stored passwords found."}
    
    # Returns the password names (Not the actual passwords for security)
    return {
        "stored_passwords": [
            {
                "id": record.id, 
                "name": record.name, 
                "created_at": record.created_at
            }
            for record in stored_passwords
        ]
    }

# ------------------------------
# Delete Stored Passwords (By User)
# ------------------------------
@router.delete("/delete-stored-password/{password_id}")
@limiter.limit("5/minute")
async def delete_stored_password(
    request: Request,
    password_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme)
):
    """
    - Allows user to delete a previously stored password.
    """
    
    # Verify user authentication 
    user = verify_access_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authentication"
        )
    
    query_result = await db.execute(select(User).where(User.email == user["sub"]))
    user_db = query_result.scalars().first()
    
    if not user_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
        
    # Fetch the password entry from the database 
    query_result = await db.execute(
        select(GeneratedPassword).where(
            GeneratedPassword.id == password_id,
            GeneratedPassword.user_id == user_db.id
    ))
    stored_password = query_result.scalars().first()
    
    if not stored_password:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Password entry not found."
        )
        
    # Delete the password entry
    await db.delete(stored_password)
    await db.commit()
    
    return {"message": "Stored password deleted successfully."}

# ------------------------------
# Download Stored Password as Text File 
# ------------------------------
@router.get("/download-password/{password_id}")
async def download_password(
    password_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme)
):
    """
    - Allows users to download a stored password as a .txt file 
    """
    
    # Verify user authentication 
    user = verify_access_token(token)
    
    query_result = await db.execute(select(User).where(User.email == user["sub"]))
    user_db = query_result.scalars().first()
    
    if not user_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    
    # Fetch the stored password 
    query_result = await db.execute(select(GeneratedPassword).where(
        GeneratedPassword.id == password_id,
        GeneratedPassword.user_id == user_db.id
    ))
    stored_password = query_result.scalars().first()
    
    if not stored_password:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Password entry not found"
        )
        
    # Create a temporary file path
    file_path = os.path.join(tempfile.gettempdir(), f"{stored_password.name}.txt")
    with open(file_path, "w") as file:
        file.write(f"Password Name: {stored_password.name}\n")
        file.write(f"Password: {stored_password.password}\n")
    
    return FileResponse(
        file_path, 
        filename=f"{stored_password.name}.txt",
        media_type='application/octet-stream'
    )
    

# ------------------------------
# Admin Password Reset Route
# ------------------------------
@router.post("/admin/reset-password")
@limiter.limit("3/minute")
async def reset_admin_password(
    request: Request,
    payload: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme)
):
    """
    Allows an authenticated admin (superadmin) to reset an admins password
    """
    
    # Verify the requester is an admin and query the database for the admin email
    current_user = verify_access_token(token)
    
    # Fetch superadmins request
    query_result = await db.execute(select(User).where(User.email == current_user["sub"]))
    requester = query_result.scalars().first()
    
    # If admin does not exist in the database or if the requesters role isn't an admin then show error message
    if not requester or requester.role != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superadmins can reset admin passwords."
        )
    
    # Fetch admins password whose password needs to be changed 
    target_result = await db.execute(
        select(User).where(User.email == payload.email)
    )
    target_user = target_result.scalars().first()
    
    if not target_user or target_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User either does not exist or they are not an admin."
        )
    
    # Update password securely 
    hashed_password = hash_password(payload.new_password, "admin")
    await db.execute(
        update(User).where(User.email == payload.email).values(hashed_password=hashed_password)
    )
    await db.commit()
    
    return {"message": "Admin password reset successfully by superadmin."}
    

@router.get("/")
async def home():
    return {"message": "Welcome to the Breach Detection API"}

@router.get("/health")
async def health_check():
    return {"status": "OK"}
