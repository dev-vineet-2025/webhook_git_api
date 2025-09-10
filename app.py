import hmac
import hashlib
import json
import os
import sys
from fastapi import FastAPI, Request, Header, HTTPException, status
from typing import Optional
import jwt
import time
import httpx
from fastapi.responses import RedirectResponse, JSONResponse

# Try to load python-dotenv if available
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("[INIT] Loaded .env file successfully")
except ImportError:
    print("[INIT] python-dotenv not installed - using system environment variables only")
    print("[INIT] To install: pip install python-dotenv")

# Load environment variables with fallbacks
GITHUB_SECRET = os.getenv("GITHUB_SECRET")
GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_PRIVATE_KEY = os.getenv("GITHUB_PRIVATE_KEY")
REDIRECT_BASE_URL = os.getenv("REDIRECT_BASE_URL", "https://6772b8710184.ngrok-free.app")


print("\n" + "="*60)

def create_jwt():
    now = int(time.time())
    payload = {
        "iat": now,
        "exp": now + (10 * 60),
        "iss": GITHUB_APP_ID
    }
    print("[JWT] Creating GitHub App JWT token...")
    return jwt.encode(payload, GITHUB_PRIVATE_KEY, algorithm="RS256")

async def make_github_api_call(access_token: str):
    print("[API] Making GitHub API call with access token")
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github.v3+json"
            }
        )
        print(f"[API] GitHub API response status: {response.status_code}")
        return response.json()

def verify_github_signature(payload: bytes, signature: str, secret: str) -> bool:
    if not signature or not signature.startswith("sha256="):
        print("[SIGNATURE] Signature missing or invalid format")
        return False

    signature_hash = signature.removeprefix("sha256=")
    hmac_digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    is_valid = hmac.compare_digest(hmac_digest, signature_hash)
    print(f"[SIGNATURE] Signature valid: {is_valid}")
    return is_valid

app = FastAPI()

@app.get("/login/github")
async def github_login():
    # Runtime check for OAuth configuration
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        error_data = {
            "error": "OAuth not configured",
            "message": "GitHub OAuth credentials are missing",
            "required": ["GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"],
            "help": "Create a GitHub OAuth App at https://github.com/settings/applications/new"
        }
        return JSONResponse(
            content=json.loads(json.dumps(error_data)),
            status_code=400
        )
    
    redirect_uri = f"{REDIRECT_BASE_URL}/callback"
    url = (
        f"https://github.com/login/oauth/authorize?"
        f"client_id={GITHUB_CLIENT_ID}&"
        f"redirect_uri={redirect_uri}&"
        "scope=repo user"
    )
    print(f"[LOGIN] Redirecting to GitHub OAuth URL:\n{url}")
    # return RedirectResponse(url)
    return JSONResponse(
        content=json.loads(json.dumps(url)),
        status_code=200
    )

@app.get("/callback")
async def github_callback(code: str):
    print(f"[CALLBACK] Received code from GitHub: {code}")
        
    # Runtime check for OAuth configuration
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        error_data = {
            "error": "OAuth not configured",
            "message": "Cannot complete OAuth flow - missing credentials",
            "required": ["GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"]
        }
        return JSONResponse(
            content=json.loads(json.dumps(error_data)),
            status_code=400
        )
    
    redirect_uri = f"{REDIRECT_BASE_URL}/callback"
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": redirect_uri
            }
        )
        print(f"[CALLBACK] GitHub token exchange status: {response.status_code}")
        data = response.json()
        print(f"[CALLBACK] Token exchange response: {data}")
        
        # Check for errors in the response
        if "error" in data:
            print(f"[CALLBACK] OAuth error: {data}")
            return RedirectResponse("/error")
        
        access_token = data.get("access_token")
        
        if access_token:
            print(f"[CALLBACK] Access token received: {access_token}")
            # TODO: Store the access token in your database/session here
            # For now, just redirect to success page
            return RedirectResponse("/success")
        else:
            print("[CALLBACK] No access token received")
            return RedirectResponse("/error")

@app.get("/success")
async def success():
    response_data = {
        "status": "success",
        "message": "GitHub OAuth authentication successful!",
        "note": "Your access token has been processed successfully."
    }
    return JSONResponse(
        content=json.loads(json.dumps(response_data)),
        status_code=200
    )

@app.get("/error")
async def error():
    response_data = {
        "status": "error",
        "message": "GitHub OAuth authentication failed.",
        "note": "Please try again by visiting /login/github"
    }
    return JSONResponse(
        content=json.loads(json.dumps(response_data)),
        status_code=400
    )

@app.post("/webhook/github")
async def github_webhook(
    request: Request,
    x_github_event: Optional[str] = Header(None)
):
    try:
        raw_payload = await request.body()
        print(f"[WEBHOOK] Received GitHub webhook: {raw_payload!r}")
        print(f"[WEBHOOK] Received GitHub event: {x_github_event}")

        if not raw_payload:
            error_data = {"error": "Empty payload"}
            return JSONResponse(
                content=json.loads(json.dumps(error_data)),
                status_code=400
            )

        # Decode JSON safely
        try:
            payload = json.loads(raw_payload.decode("utf-8"))
        except json.JSONDecodeError as e:
            print(f"[WEBHOOK] Failed to decode JSON: {e}")
            error_data = {"error": "Invalid JSON payload"}
            return JSONResponse(
                content=json.loads(json.dumps(error_data)),
                status_code=400
            )

        print(f"[WEBHOOK] Payload keys: {list(payload.keys())}")

        response_data = {"status": "Webhook processed", "event": x_github_event}
        return JSONResponse(
            content=json.loads(json.dumps(response_data)),
            status_code=200
        )

    except Exception as e:
        print(f"[WEBHOOK] Exception: {e}")
        raise HTTPException(status_code=500, detail="Internal error")


@app.get("/health")
async def health_check():
    print("[HEALTH] Health check called")
    response_data = {"status": "healthy"}
    return JSONResponse(
        content=json.loads(json.dumps(response_data)),
        status_code=200
    )

if __name__ == "__main__":
    import uvicorn
    print("[INIT] Starting FastAPI app...")
    uvicorn.run(app, host="0.0.0.0", port=8000)