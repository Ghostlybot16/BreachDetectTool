from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from .config import app_config

# Create an async database engine
engine = create_async_engine(app_config.DATABASE_URL, echo=True, future=True)

#Create an async session factory
async_session_maker = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# Dependency function to get an async database session
async def get_db():
    async with async_session_maker() as session:
        try:
            yield session # Provide the session to the request
        finally:
            await session.close() # Ensure session is closed properly 