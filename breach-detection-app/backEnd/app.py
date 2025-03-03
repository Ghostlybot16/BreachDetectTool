from fastapi import FastAPI
from routes import router # Import API routes

app = FastAPI(title="Breach Detection API")

# Include routes from routes.py
app.include_router(router)

# Health check
@app.get("/ping")
async def ping():
    return {"message": "API is working!"}
