"""
sal-auth Configuration
"""
import os
from pathlib import Path
from pydantic_settings import BaseSettings
from typing import List, Optional

class Settings(BaseSettings):
    # Server
    host: str = "0.0.0.0"
    port: int = 8200
    debug: bool = True
    
    # Security
    secret_key: str = "sal-auth-secret-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 30
    
    # OAuth
    issuer: str = "http://localhost:8200"
    authorization_endpoint: str = "/authorize"
    token_endpoint: str = "/token"
    userinfo_endpoint: str = "/userinfo"
    
    # Database
    database_url: str = "sqlite+aiosqlite:///./sal_auth.db"
    
    # BBID
    bbid_encryption_key: str = "bbid-encryption-key-change-me"
    bbid_prefix: str = "⠠⠎⠁⠇_"
    
    # Allowed clients
    allowed_clients: List[str] = [
        "sal-voice",
        "sal-llm",
        "sal-prod",
        "braillebuddy",
        "consciousness-bridge"
    ]
    
    # CORS
    allowed_origins: List[str] = ["*"]
    
    class Config:
        env_file = ".env"
        env_prefix = "SAL_AUTH_"

settings = Settings()
