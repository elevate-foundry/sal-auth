"""
sal-auth Database Models
"""
import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy import Column, String, DateTime, Boolean, Text, ForeignKey, JSON
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

from config import settings

Base = declarative_base()


class User(Base):
    """User account with BBID"""
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True)
    password_hash = Column(String(255), nullable=False)
    
    # BBID - Braille Buddy Identity
    bbid = Column(String(512), unique=True, nullable=True)  # 8-dot braille identity
    bbid_created_at = Column(DateTime, nullable=True)
    
    # Profile
    display_name = Column(String(255), nullable=True)
    preferred_modalities = Column(JSON, default=["text", "voice", "braille"])
    preferred_language = Column(String(10), default="en")
    
    # Status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    tokens = relationship("Token", back_populates="user", cascade="all, delete-orphan")
    biometrics = relationship("BiometricCredential", back_populates="user", cascade="all, delete-orphan")


class Token(Base):
    """OAuth tokens"""
    __tablename__ = "tokens"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    
    access_token = Column(String(512), unique=True, nullable=False)
    refresh_token = Column(String(512), unique=True, nullable=True)
    token_type = Column(String(50), default="bearer")
    
    # Braille signature embedded in token
    braille_signature = Column(String(256), nullable=True)
    
    scope = Column(String(512), nullable=True)
    expires_at = Column(DateTime, nullable=False)
    refresh_expires_at = Column(DateTime, nullable=True)
    
    client_id = Column(String(255), nullable=True)
    is_revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="tokens")


class OAuthClient(Base):
    """Registered OAuth clients (sal-voice, sal-llm, etc.)"""
    __tablename__ = "oauth_clients"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    client_id = Column(String(255), unique=True, nullable=False)
    client_secret_hash = Column(String(255), nullable=False)
    
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Braille identity for the client
    client_bbid = Column(String(256), nullable=True)
    
    redirect_uris = Column(JSON, default=[])
    allowed_scopes = Column(JSON, default=["openid", "profile", "bbid"])
    grant_types = Column(JSON, default=["authorization_code", "refresh_token", "client_credentials"])
    
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class BiometricCredential(Base):
    """Biometric credentials for BBID authentication"""
    __tablename__ = "biometric_credentials"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    
    credential_type = Column(String(50), nullable=False)  # fingerprint, voice, face
    credential_id = Column(String(512), unique=True, nullable=False)
    public_key = Column(Text, nullable=True)
    
    # Braille encoding of biometric
    braille_encoding = Column(String(512), nullable=True)
    
    device_name = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime, nullable=True)
    
    user = relationship("User", back_populates="biometrics")


# Database engine and session
engine = create_async_engine(settings.database_url, echo=settings.debug)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db():
    """Initialize database tables"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncSession:
    """Get database session"""
    async with async_session() as session:
        yield session
