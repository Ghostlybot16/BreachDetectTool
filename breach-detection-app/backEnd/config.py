from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import os

# Load the .env file 
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

class AppConfig(BaseSettings):
    DB_USER: str
    DB_PASS: str
    DB_HOST: str
    DB_NAME: str
    SECRET_KEY: str
    JWT_SECRET_KEY: str
    JWT_PRIVATE_KEY: str
    JWT_PUBLIC_KEY: str
    JWT_ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    @property
    def DATABASE_URL(self):
        return f"postgresql+asyncpg://{self.DB_USER}:{self.DB_PASS}@{self.DB_HOST}/{self.DB_NAME}"
    
    class Config:
        env_file = ".env"
        case_sensitive = True

app_config = AppConfig()