import re

import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-kn7icg7y.apps.exam.local"

# PASTE the public key from the exam page here, exactly as shown
# (BEGIN/END lines included). Copy-paste it; do not retype it.
PUBLIC_KEY_RAW = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----
"""


def normalize_pem(raw: str) -> str:
    """Rebuild a clean PEM even if line breaks/spaces got mangled on paste."""
    body = re.sub(r"-----(BEGIN|END) PUBLIC KEY-----", "", raw)
    body = re.sub(r"\s+", "", body)
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"


PUBLIC_KEY = normalize_pem(PUBLIC_KEY_RAW)

app = FastAPI()


def invalid(status: int = 401):
    return JSONResponse(status_code=status, content={"valid": False})


@app.post("/verify")
async def verify(request: Request):
    try:
        body = await request.json()
        token = body.get("token")
        if not isinstance(token, str) or not token:
            return invalid(400)
    except Exception:
        return invalid(400)

    try:
        claims = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],  # never accept alg=none / HS256
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iss", "aud"], "verify_exp": True},
        )
    except Exception:
        return invalid(401)

    return {
        "valid": True,
        "email": claims.get("email"),
        "sub": claims.get("sub"),
        "aud": claims.get("aud"),
    }


@app.get("/")
async def root():
    return {"status": "ok"}
