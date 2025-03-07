from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from slowapi.middleware import SlowAPIASGIMiddleware
from slowapi.errors import RateLimitExceeded
from routes import router # Import API routes
from limiter import limiter # Import limiter from limiter.py

# FastAPI app instance
app = FastAPI(title="Breach Detection API")

app.state.limiter = limiter

# Add rate limiting middleware 
app.add_middleware(SlowAPIASGIMiddleware)

# Include routes from routes.py
app.include_router(router)

# Health check
@app.get("/ping")
async def ping():
    return {"message": "API is working!"}

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"error": "Rate limit exceeded. Try again leter."}
    )
