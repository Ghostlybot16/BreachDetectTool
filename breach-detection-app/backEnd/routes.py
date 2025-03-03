# This file contains API endpoints for the FastAPI backend

from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def home():
    return {"message": "Welcome to the Breach Detection API"}

@router.get("/health")
async def health_check():
    return {"status": "OK"}
