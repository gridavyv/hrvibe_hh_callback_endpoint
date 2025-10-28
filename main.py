import os, time, json, hmac, hashlib
from typing import Dict, Optional
from collections import deque
import httpx
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import PlainTextResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI()

# --- Config ---
ADMIN_TOKEN       = os.getenv("ADMIN_TOKEN")
BOT_SHARED_SECRET = os.getenv("BOT_SHARED_SECRET")

HH_CLIENT_ID      = os.getenv("HH_CLIENT_ID")
HH_CLIENT_SECRET  = os.getenv("HH_CLIENT_SECRET")
HH_REDIRECT_URI   = os.getenv("HH_REDIRECT_URI")

HH_TOKEN_URL      = os.getenv("HH_TOKEN_URL", "https://hh.ru/oauth/token")
USER_AGENT        = os.getenv("USER_AGENT")

# --- Simple in-memory stores ---
BUFFER_MAX = 200
pending = deque(maxlen=BUFFER_MAX)          # raw callback hits (for audit)
# tokens is nested dictionary keyed by state
# key: state, value: {access_token, refresh_token, token_type, scope, expires_at:int}
tokens: Dict[str, Dict] = {}

# --- Models ---
class StatePayload(BaseModel):
    state: str

# --- Helpers ---
async def exchange_code_for_tokens(code: str) -> Dict:
    """
    Exchange HH OAuth code for tokens from HH API.
    Gets access_token, token_type, expires_in, refresh_token
    Calculates the timestamp for the expiration of the access_token 
    Returns a dictionary with access_token, token_type, expires_in, refresh_token, expires_at - computed absolute timestamp.
    """
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": USER_AGENT
        }
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": HH_REDIRECT_URI,
        "client_id": HH_CLIENT_ID,
        "client_secret": HH_CLIENT_SECRET,
    }
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(HH_TOKEN_URL, data=data, headers=headers) 
        r.raise_for_status()
        j = r.json()
    # HH typically returns: access_token, token_type, expires_in, refresh_token
    now = int(time.time())
    # we add to dict "expires_at" the current time plus the number of seconds in the "expires_in" field
    j["expires_at"] = now + int(j.get("expires_in", 3600))
    # return the dictionary with tokens and the computed expires_at absolute timestamp
    return j

async def refresh_with_refresh_token(refresh_token: str) -> Dict:
    """
    Refresh HH tokens using a refresh_token from HH API.
    Gets {access_token, token_type, expires_in, refresh_token}
    Calculates the timestamp for the expiration of the access_token 
    Returns a dictionary with {access_token, token_type, expires_in, refresh_token, expires_at - computed absolute timestamp}.
    """
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": USER_AGENT
        }
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": HH_CLIENT_ID,
        "client_secret": HH_CLIENT_SECRET,
        "redirect_uri": HH_REDIRECT_URI,
    }
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(HH_TOKEN_URL, data=data, headers=headers)
        r.raise_for_status()
        j = r.json()
    now = int(time.time())
    j["expires_at"] = now + int(j.get("expires_in", 3600))
    return j

async def get_valid_access_token_for_state(state: str) -> Optional[Dict]:
    """
    Returns dict with {access_token, token_type, expires_in, refresh_token, expires_at - computed absolute timestamp}, 
    Refreshing tokens if expiration is within 60 seconds.
    """
    # get the value from the tokens dictionary by key "state"
    item = tokens.get(state)
    if not item:
        return None
    # refresh tokens if "expires_at" is less than 60 seconds from the current time
    if int(time.time()) >= int(item["expires_at"]) - 60:
        refreshed = await refresh_with_refresh_token(item["refresh_token"])
        tokens[state] = {
            "access_token": refreshed["access_token"],
            "refresh_token": refreshed.get("refresh_token", item["refresh_token"]),  # HH may rotate or not
            "token_type": refreshed.get("token_type", "Bearer"),
            "expires_in": refreshed.get("expires_in"),
            "expires_at": refreshed["expires_at"],
        }
        item = tokens[state]
    return item

def require_admin(admin_token: str):
    if admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

def require_bot(auth_header: Optional[str]):
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    if auth_header.split(" ", 1)[1].strip() != BOT_SHARED_SECRET:
        raise HTTPException(status_code=401, detail="Invalid bearer token")


# --- Endpoints ---

# Health check endpoint to verify the service is running
@app.get("/")
def health():
    return PlainTextResponse("Endpoint is available")

# HH redirect target: /hh/callback?code=...&state=...
@app.get("/hh/callback")
async def hh_callback(request: Request):
    # Capture code and state from request query parameters
    code  = request.query_params.get("code")
    state = request.query_params.get("state")
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code/state")
    # audit trail
    item = {
        "state": state,
        "code": code,
        "ts": int(time.time()),
        "ip": request.client.host if request.client else None,
    }
    pending.append(item)

    # Immediately exchange the code -> tokens and store in memory under variable called "tokens"
    try:
        # HH typically returns: access_token, token_type, expires_in, refresh_token
        # await is used to wait for the coroutine to complete
        token = await exchange_code_for_tokens(code)
        tokens[state] = {
            "access_token": token["access_token"],
            "refresh_token": token.get("refresh_token"),
            "token_type": token.get("token_type", "Bearer"),
            "expires_in": token.get("expires_in"),
            "expires_at": token["expires_at"],
        }
        return PlainTextResponse("Вы успешно авторизовались в HH.ru, можете вернуться в Telegram")
    except httpx.HTTPError as e:
        # keep the pending record, but don’t store tokens
        return PlainTextResponse(f"Ошибка авторизации: {str(e)}", status_code=500)

# Bot → Render: return a valid access token for a given state (refreshing if needed)
@app.post("/token/by-state")
# payload: StatePayload -> comes from the request body (JSON)
# authorization: Optional[str] = Header(None) -> FastAPI automatically maps that HTTP header to the Python parameter "authorization".
async def token_by_state(payload: StatePayload, authorization: Optional[str] = Header(None)):
    #check Bearer and BOT_SHARED_SECRET in the authorization header
    require_bot(authorization)
    # get the valid access token for the given "state" from the tokens dictionary
    item = await get_valid_access_token_for_state(payload.state)
    # if not found, return 404 error
    if not item:
        raise HTTPException(status_code=404, detail="State not ready or not found")
    return {
        "access_token": item["access_token"],
        "token_type": item.get("token_type", "Bearer"),
        "expires_in": item.get("expires_in"),
        "expires_at": item["expires_at"],
    }

# Optional: one-shot dequeue/cleanup after you’ve stored the mapping user ↔ tokens elsewhere
@app.delete("/admin/state")
# payload: StatePayload -> comes from the request body (JSON)
# authorization: Optional[str] = Header(None) -> FastAPI automatically maps that HTTP header to the Python parameter "admin_token".
def admin_delete_state(payload: StatePayload, admin_token: Optional[str] = Header(None)):
    #check ADMIN_TOKEN in the authorization header
    require_admin(admin_token)
    #using .pop() method remove the item with key "state" and returns its value. 
    #if key is not found, returns default (None)
    existed = tokens.pop(payload.state, None)
    #If a token was found and removed → "existed" is a dictionary → bool(existed) = True
    #If no token is not removed → "existed" = None → bool(existed) = False
    return {"deleted": bool(existed)} 

@app.get("/admin/pending")
def admin_pending(admin_token: Optional[str] = Header(None)):
    #check ADMIN_TOKEN in the authorization header
    require_admin(admin_token)
    return JSONResponse(list(pending))

@app.get("/admin/tokens")
def admin_tokens(admin_token: Optional[str] = Header(None)):
    #check ADMIN_TOKEN in the authorization header
    require_admin(admin_token)
    #builds and returns a JSON response showing all tokens in memory, but with their sensitive parts (access and refresh tokens) hidden by replacing them with "***".
    return JSONResponse({k: {**v, "access_token": "***", "refresh_token": "***"} for k, v in tokens.items()})
