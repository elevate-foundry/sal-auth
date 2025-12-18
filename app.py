"""
sal-auth - BBID OAuth Provider
FastAPI application providing OAuth 2.0/OIDC with BrailleBuddy Identity
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from passlib.context import CryptContext
from jose import jwt, JWTError
from pydantic import BaseModel
from loguru import logger

from config import settings
from models import User, Token, OAuthClient, init_db, get_db, async_session
from bbid import bbid_generator, bbid_token_encoder, BBID


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("⠠⠎⠁⠇_⠁⠥⠞⠓ Starting up...")
    await init_db()
    yield
    logger.info("⠠⠎⠁⠇_⠁⠥⠞⠓ Shutting down...")


app = FastAPI(
    title="sal-auth",
    description="BBID OAuth Provider for SAL",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)


# --- Pydantic Models ---

class UserCreate(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    display_name: Optional[str] = None

class UserResponse(BaseModel):
    id: str
    username: str
    email: Optional[str]
    bbid: Optional[str]
    display_name: Optional[str]
    preferred_modalities: list
    
class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: Optional[str] = None
    bbid: Optional[str] = None
    braille_signature: Optional[str] = None

class BBIDResponse(BaseModel):
    bbid: str
    display: str
    haptic_pattern: list
    created_at: str


# --- Helper Functions ---

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    to_encode.update({"exp": expire, "iss": settings.issuer})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    if not token:
        return None
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        user_id = payload.get("sub")
        if not user_id:
            return None
        result = await db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()
    except JWTError:
        return None


# --- Endpoints ---

@app.get("/", response_class=HTMLResponse)
async def root():
    return """
<!DOCTYPE html>
<html>
<head>
    <title>⠠⠎⠁⠇_⠁⠥⠞⠓ - SAL Auth</title>
    <style>
        body { font-family: system-ui; background: #1a1a2e; color: #eee; padding: 40px; text-align: center; }
        h1 { background: linear-gradient(90deg, #00d9ff, #00ff88); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .braille { font-size: 2em; letter-spacing: 5px; margin: 20px 0; }
        .card { background: rgba(255,255,255,0.05); border-radius: 16px; padding: 30px; max-width: 500px; margin: 30px auto; }
        a { color: #00d9ff; }
        code { background: rgba(0,0,0,0.3); padding: 2px 8px; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>🔐 sal-auth</h1>
    <div class="braille">⠠⠎⠁⠇_⠁⠥⠞⠓</div>
    <p>BBID OAuth Provider for the Semantic Accessibility Layer</p>
    
    <div class="card">
        <h3>Endpoints</h3>
        <p><code>POST /api/register</code> - Register new user</p>
        <p><code>POST /token</code> - Get access token</p>
        <p><code>GET /api/bbid</code> - Get your BBID</p>
        <p><code>GET /.well-known/openid-configuration</code> - OIDC Discovery</p>
    </div>
    
    <div class="card">
        <h3>Features</h3>
        <p>✓ OAuth 2.0 / OpenID Connect</p>
        <p>✓ 8-dot Braille Identity (BBID)</p>
        <p>✓ Multi-modal authentication</p>
        <p>✓ Cross-project SSO</p>
    </div>
</body>
</html>
"""


@app.get("/.well-known/openid-configuration")
async def openid_configuration():
    """OIDC Discovery endpoint"""
    return {
        "issuer": settings.issuer,
        "authorization_endpoint": f"{settings.issuer}/authorize",
        "token_endpoint": f"{settings.issuer}/token",
        "userinfo_endpoint": f"{settings.issuer}/userinfo",
        "jwks_uri": f"{settings.issuer}/.well-known/jwks.json",
        "scopes_supported": ["openid", "profile", "email", "bbid"],
        "response_types_supported": ["code", "token"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials", "password"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "name", "email", "bbid", "bbid_sig", "modalities"]
    }


@app.post("/api/register", response_model=UserResponse)
async def register(user_data: UserCreate):
    """Register a new user with BBID"""
    async with async_session() as db:
        # Check if username exists
        result = await db.execute(select(User).where(User.username == user_data.username))
        if result.scalar_one_or_none():
            raise HTTPException(400, "Username already registered")
            
        # Create user
        user = User(
            username=user_data.username,
            email=user_data.email,
            password_hash=hash_password(user_data.password),
            display_name=user_data.display_name or user_data.username
        )
        
        db.add(user)
        await db.flush()
        
        # Generate BBID
        bbid = bbid_generator.generate(user.id, user.username)
        user.bbid = bbid.display
        user.bbid_created_at = bbid.created_at
        
        await db.commit()
        await db.refresh(user)
        
        logger.info(f"Registered user: {user.username} with BBID: {user.bbid}")
        
        return UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            bbid=user.bbid,
            display_name=user.display_name,
            preferred_modalities=user.preferred_modalities
        )


@app.post("/token", response_model=TokenResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """OAuth token endpoint with BBID enhancement"""
    async with async_session() as db:
        result = await db.execute(select(User).where(User.username == form_data.username))
        user = result.scalar_one_or_none()
        
        if not user or not verify_password(form_data.password, user.password_hash):
            raise HTTPException(401, "Invalid credentials")
            
        # Create BBID-enhanced token
        bbid_obj = BBID(
            braille=user.bbid.replace(settings.bbid_prefix, "") if user.bbid else "",
            user_id=user.id,
            created_at=user.bbid_created_at or datetime.utcnow(),
            signature=""
        )
        
        token_data = {
            "sub": user.id,
            "username": user.username,
            **bbid_token_encoder.create_token_claims(user.id, bbid_obj)
        }
        
        access_token = create_access_token(token_data)
        refresh_token = secrets.token_urlsafe(32)
        
        # Store token
        token = Token(
            user_id=user.id,
            access_token=access_token,
            refresh_token=refresh_token,
            braille_signature=bbid_obj.signature if bbid_obj else None,
            expires_at=datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes),
            refresh_expires_at=datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)
        )
        db.add(token)
        
        user.last_login = datetime.utcnow()
        await db.commit()
        
        logger.info(f"Token issued for: {user.username}")
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.access_token_expire_minutes * 60,
            refresh_token=refresh_token,
            bbid=user.bbid,
            braille_signature=token.braille_signature
        )


@app.get("/userinfo")
async def userinfo(current_user: User = Depends(get_current_user)):
    """OIDC UserInfo endpoint"""
    if not current_user:
        raise HTTPException(401, "Not authenticated")
        
    return {
        "sub": current_user.id,
        "name": current_user.display_name,
        "preferred_username": current_user.username,
        "email": current_user.email,
        "bbid": current_user.bbid,
        "modalities": current_user.preferred_modalities
    }


@app.get("/api/bbid", response_model=BBIDResponse)
async def get_bbid(current_user: User = Depends(get_current_user)):
    """Get user's BBID with haptic pattern"""
    if not current_user:
        raise HTTPException(401, "Not authenticated")
        
    if not current_user.bbid:
        raise HTTPException(404, "BBID not generated")
        
    bbid_obj = BBID(
        braille=current_user.bbid.replace(settings.bbid_prefix, ""),
        user_id=current_user.id,
        created_at=current_user.bbid_created_at or datetime.utcnow(),
        signature=""
    )
    
    return BBIDResponse(
        bbid=current_user.bbid,
        display=bbid_obj.display,
        haptic_pattern=bbid_obj.haptic_pattern,
        created_at=bbid_obj.created_at.isoformat()
    )


@app.get("/api/braille/encode/{text}")
async def encode_to_braille(text: str):
    """Encode text to 8-dot braille"""
    braille = bbid_generator.encode_text_to_bbid_style(text)
    return {"text": text, "braille": braille}


@app.get("/api/braille/decode/{braille}")
async def decode_from_braille(braille: str):
    """Decode 8-dot braille to text (lossy)"""
    text = bbid_generator.decode_bbid_to_text(braille)
    return {"braille": braille, "text": text}


@app.post("/api/verify-token")
async def verify_token(token: str = Form(...)):
    """Verify a token and return claims"""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        return {"valid": True, "claims": payload}
    except JWTError as e:
        return {"valid": False, "error": str(e)}


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "sal-auth",
        "version": "1.0.0",
        "braille": "⠠⠎⠁⠇_⠁⠥⠞⠓"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host=settings.host, port=settings.port, reload=settings.debug)
