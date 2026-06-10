# sal-auth 🔐

**BBID OAuth Provider for SAL (Semantic Accessibility Layer)**

Unified authentication across all SAL projects using BrailleBuddy Identity (BBID).

## ⠠⠎⠁⠇_⠁⠥⠞⠓ Architecture

```
[sal-voice]  ─┐
[sal-llm]    ─┼─→ [sal-auth] ←─→ [BBID Identity]
[sal-prod]   ─┤      ↓
[BrailleBuddy]┘   [OAuth 2.0 / OIDC]
                      ↓
              [JWT + 8-dot Braille Signature]
```

## Features

- **OAuth 2.0 / OpenID Connect** compliant provider
- **BBID Integration**: Braille-encoded identity with biometrics
- **8-dot Braille Signatures**: Tokens include braille identity markers
- **Multi-modal Auth**: Voice, fingerprint, braille pattern recognition
- **Cross-project SSO**: Single sign-on across all SAL services
- **Accessibility-first**: WCAG AAA compliant authentication flows

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Initialize database
python init_db.py

# Run auth server
python app.py

# Open http://localhost:8200
```

## API Endpoints

### OAuth 2.0
- `GET /authorize` - Authorization endpoint
- `POST /token` - Token endpoint
- `POST /revoke` - Token revocation
- `GET /userinfo` - User info (OIDC)
- `GET /.well-known/openid-configuration` - OIDC discovery

### BBID
- `POST /api/bbid/register` - Register new BBID
- `POST /api/bbid/authenticate` - Authenticate with BBID
- `GET /api/bbid/identity` - Get braille identity
- `POST /api/bbid/biometric` - Biometric verification

### 8-dot Braille
- `GET /api/braille/encode/{text}` - Encode to 8-dot braille
- `GET /api/braille/decode/{braille}` - Decode from 8-dot braille
- `POST /api/braille/verify-signature` - Verify braille signature

## Environment Variables

```bash
SAL_AUTH_SECRET_KEY=your-secret-key
SAL_AUTH_DATABASE_URL=sqlite:///sal_auth.db
SAL_AUTH_ISSUER=http://localhost:8200
SAL_AUTH_TOKEN_EXPIRY=3600
BBID_ENCRYPTION_KEY=your-bbid-key
```

## Client Integration

```python
from sal_auth import SALAuthClient

client = SALAuthClient(
    auth_url="http://localhost:8200",
    client_id="sal-voice",
    client_secret="..."
)

# Get access token
token = await client.get_token(username="user", password="pass")

# Verify BBID
identity = await client.verify_bbid(bbid_token)

# Braille signature
signature = client.sign_with_braille(data, user_bbid)
```

## Token Structure

SAL tokens include 8-dot braille identity markers:

```json
{
  "sub": "user-uuid",
  "iss": "sal-auth",
  "bbid": "⠠⠎⠁⠇_⠥⠎⠑⠗_⠁⠃⠉⠙",
  "braille_signature": "⠠⠧⠑⠗⠊⠋⠊⠑⠙",
  "modalities": ["voice", "text", "braille", "haptic"],
  "exp": 1703001600
}
```

---

**⠠⠎⠁⠇_⠁⠥⠞⠓_⠁⠉⠞⠊⠧⠑** - SAL Auth Active

<!-- ELEVATE:BEGIN (auto-generated section; edits here are overwritten) -->
## About

| | |
| --- | --- |
| **Description** | SAL Auth - BBID OAuth provider with 8-dot braille identity |
| **Language** | Python |
| **Commits** | 2 |
| **Created** | 2025-12-18 |
| **Last push** | 2026-05-19 |

Part of [**elevate-foundry**](https://github.com/elevate-foundry) · [repository](https://github.com/elevate-foundry/sal-auth)
<!-- ELEVATE:END -->
