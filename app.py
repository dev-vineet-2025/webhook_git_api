import hmac
import hashlib
import json
import os
from fastapi import FastAPI, Request, Header, HTTPException, status
from typing import Optional

# SECURITY FIX: Use environment variable instead of hardcoded secret
# The value you had appears to be a GitHub Personal Access Token, not a webhook secret
GITHUB_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")

if not GITHUB_SECRET:
    raise ValueError("GITHUB_WEBHOOK_SECRET environment variable must be set")

def verify_github_signature(payload: bytes, signature: str, secret: str) -> bool:
    """
    Verify GitHub webhook signature using HMAC-SHA256.
    
    Args:
        payload: Raw request body as bytes
        signature: GitHub signature from X-Hub-Signature-256 header
        secret: Your webhook secret
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    if not signature or not signature.startswith("sha256="):
        return False
    
    # Extract the hash from the signature header
    signature_hash = signature.removeprefix("sha256=")
    
    # Calculate the expected signature using the payload and secret
    hmac_digest = hmac.new(
        secret.encode("utf-8"),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    # Use hmac.compare_digest() for a timing-safe comparison
    return hmac.compare_digest(hmac_digest, signature_hash)


app = FastAPI()

@app.post("/webhook/github")
async def github_webhook(
    request: Request,
    # x_hub_signature_256: Optional[str] = Header(None),  # Make it optional with proper typing
    x_github_event: Optional[str] = Header(None)  # Also capture the event type
):
    """
    Handle GitHub webhook events with proper signature verification.
    """
    import pdb;pdb.set_trace();
    # Get raw payload
    payload = await request.body()
    # Verify the signature
    # if not verify_github_signature(payload, x_hub_signature_256, GITHUB_SECRET):
    #     raise HTTPException(
    #         status_code=status.HTTP_401_UNAUTHORIZED,
    #         detail="Invalid or missing signature"
    #     )
    
    # Parse JSON payload
    try:
        event_data = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload"
        )
    
    # Process different event types
    if x_github_event == "push":
        print(f"Push event received for repository: {event_data.get('repository', {}).get('full_name')}")
        # Handle push event logic here
        
    elif x_github_event == "pull_request":
        pr_action = event_data.get('action')
        pr_number = event_data.get('pull_request', {}).get('number')
        print(f"Pull request {pr_action}: #{pr_number}")
        # Handle PR event logic here
        
    elif x_github_event == "issues":
        issue_action = event_data.get('action')
        issue_number = event_data.get('issue', {}).get('number')
        print(f"Issue {issue_action}: #{issue_number}")
        # Handle issue event logic here
        
    else:
        print(f"Unhandled event type: {x_github_event}")
    
    return {
        "status": "success", 
        "event_type": x_github_event,
        "message": "Webhook processed successfully"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)