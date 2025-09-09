import hmac
import hashlib
import json
import os
from fastapi import FastAPI, Request, Header, HTTPException, status
from typing import Optional
import jwt
import time
import httpx
from fastapi.responses import RedirectResponse

# Load environment variables
GITHUB_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_PRIVATE_KEY = os.getenv("GITHUB_PRIVATE_KEY")

print(f"[INIT] GITHUB_CLIENT_ID: {GITHUB_CLIENT_ID}")
print(f"[INIT] GITHUB_CLIENT_SECRET: {GITHUB_CLIENT_SECRET}")
print(f"[INIT] GITHUB_APP_ID: {GITHUB_APP_ID}")
print(f"[INIT] GITHUB_SECRET is {'set' if GITHUB_SECRET else 'NOT set'}")
print(f"[INIT] GITHUB_PRIVATE_KEY is {'set' if GITHUB_PRIVATE_KEY else 'NOT set'}")

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
    redirect_uri = "https://6772b8710184.ngrok-free.app/callback"
    url = (
        f"https://github.com/login/oauth/authorize?"
        f"client_id={GITHUB_CLIENT_ID}&"
        f"redirect_uri={redirect_uri}&"
        "scope=repo user"
    )
    print(f"[LOGIN] Redirecting to GitHub OAuth URL:\n{url}")
    return RedirectResponse(url)

@app.get("/callback")
async def github_callback(code: str):
    print(f"[CALLBACK] Received code from GitHub: {code}")
    redirect_uri = "https://6772b8710184.ngrok-free.app/callback"
    
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
    return {
        "status": "success",
        "message": "GitHub OAuth authentication successful!",
        "note": "Your access token has been processed successfully."
    }

@app.get("/error")
async def error():
    return {
        "status": "error",
        "message": "GitHub OAuth authentication failed.",
        "note": "Please try again by visiting /login/github"
    }

@app.post("/webhook/github")
async def github_webhook(
    request: Request,
    x_github_event: Optional[str] = Header(None)
):
    payload = await request.body()
    print(f"[WEBHOOK] Received GitHub event: {x_github_event}")
    print(f"[WEBHOOK] Raw payload: {payload.decode('utf-8')}")

    try:
        event_data = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError:
        print("[WEBHOOK] Failed to decode JSON")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload"
        )

    if x_github_event == "push":
        print(f"[WEBHOOK] Push event for repo: {event_data.get('repository', {}).get('full_name')}")
    elif x_github_event == "pull_request":
        pr_action = event_data.get('action')
        pr_number = event_data.get('pull_request', {}).get('number')
        print(f"[WEBHOOK] Pull request {pr_action}: #{pr_number}")
    elif x_github_event == "issues":
        issue_action = event_data.get('action')
        issue_number = event_data.get('issue', {}).get('number')
        print(f"[WEBHOOK] Issue {issue_action}: #{issue_number}")
    else:
        print(f"[WEBHOOK] Unhandled event type: {x_github_event}")

    return {
        "status": "success",
        "event_type": x_github_event,
        "message": "Webhook processed successfully"
    }

@app.get("/health")
async def health_check():
    print("[HEALTH] Health check called")
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    print("[INIT] Starting FastAPI app...")
    uvicorn.run(app, host="0.0.0.0", port=8000)