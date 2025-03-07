import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

class Config:
    DATABASE_URL = f"postgresql+asyncpg://{os.getenv('DB_USER')}:{os.getenv('DB_PASS')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
    SECRET_KEY = os.getenv("SECRET_KEY")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    JWT_PRIVATE_KEY = os.getenv("JWT_PRIVATE_KEY")
    JWT_PUBLIC_KEY = os.getenv("JWT_PUBLIC_KEY")
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

app_config = Config()