import os, time, json, hmac, hashlib, asyncio, tempfile
from typing import Dict, Optional, Any
from collections import deque
from pathlib import Path
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

# Persistent storage location (Render Persistent Disk mount; set PERSIST_DIR if different)
PERSIST_DIR   = Path(os.getenv("PERSIST_DIR", "/var/data"))
TOKENS_PATH   = PERSIST_DIR / "tokens.json"
PENDING_PATH  = PERSIST_DIR / "pending.json"


# --- Simple in-memory stores ---
BUFFER_MAX = 200
#for storing in memory we use specialized data structure optimized "deque" for fast appends and pops from both ends
#this is C-implemented class with internal pointers and optional maxlen.
pending = deque(maxlen=BUFFER_MAX)          # raw callback hits (for audit)
# tokens is nested dictionary keyed by state
# key: state, value: {access_token, refresh_token, token_type, scope, expires_at:int}
tokens: Dict[str, Dict] = {}

# --- Models ---
#Required for parsing the request body (JSON)
class StatePayload(BaseModel):
    state: str

# --- Persistence helpers ---
def _ensure_persist_dir():
    # "exists_ok=True" means that if the directory already exists, it will not do anything and not raise an error
    PERSIST_DIR.mkdir(parents=True, exist_ok=True)

def _atomic_write_json(path: Path, data) -> None:
    """Write JSON atomically to avoid partial writes or corrupted JSON files on crashes or restarts."""
    _ensure_persist_dir()
    #argument "data" can be either a deque or a plain dictionary
    #if it is a deque, we convert it to a plain list before dumping to JSON, otherwise get error "TypeError: can't serialize deque"
    # for that, we use built-in function "isinstance" to checks whether an object belongs to deque or not
    if isinstance(data, deque):
        serializable = list(data)
    else:
        serializable = data
    # create a temporary file in the same directory as the target file, with the same name but with .tmp suffix
    tmp_fd, tmp_path = tempfile.mkstemp(dir=str(PERSIST_DIR), prefix=path.name, suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w") as f:
            # dump the serializable data to the temporary file
            json.dump(serializable, f, ensure_ascii=False, indent=2)
            # flush the file to ensure data is written to disk
            # hand it off to the operating system everything you’ve written into the file object’s internal buffer
            f.flush()
            # ensure data is written to disk instead of RAM
            # write everything in the OS’s cache for this file descriptor to the physical disk
            os.fsync(f.fileno())
        # delete old file and replace it with the temporary file atomically, then rename the temporary file to the target file name
        os.replace(tmp_path, path)
    # regardless of whether the operation was successful or not, we ensure the temporary file is deleted
    finally:
        try:
            # check if the temporary file exists
            if os.path.exists(tmp_path):
                #Deletes that leftover temp file.
                os.unlink(tmp_path)
        except Exception:
            pass

def _load_json_or_default(path: Path, default: Any) -> Any:
    """Load JSON from file, returning empty dictionary if file is missing or corrupt."""
    # try to open the file and load the JSON data from it
    try:
        with open(path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except json.JSONDecodeError:
        # Corrupt file: keep default but do not overwrite automatically
        return default

def save_tokens():
    _atomic_write_json(TOKENS_PATH, tokens)

def save_pending():
    # pending is deque, so we convert it to a plain list before dumping to JSON otherwise get error "TypeError: can't serialize deque"
    _atomic_write_json(PENDING_PATH, pending)

def load_all():
    # tokens
    loaded_tokens = _load_json_or_default(path=TOKENS_PATH, default={})
    # check if the loaded data is a dictionary using built-in function "isinstance"
    if isinstance(loaded_tokens, dict):
        # sanitize numeric fields just in case
        # When read JSON from disk, the data might technically load fine, but may be inconsistent to use directly in memory.
        # The iteration ensures that what you load is actually valid, type-consistent, and won’t crash your logic later.
        for key, value in list(loaded_tokens.items()):
            if not isinstance(value, dict):
                # remove the key-value pair from the dictionary if the value is not a dictionary
                loaded_tokens.pop(key, None)
                continue
            if "expires_at" in value:
                try:
                    value["expires_at"] = int(value["expires_at"])
                except Exception:
                    value["expires_at"] = int(time.time()) + 300    
    else:
        loaded_tokens = {}
    #Removes all existing key–value pairs from the global "tokens" dictionary
    tokens.clear()
    #Update the global "tokens" dictionary with the loaded data
    tokens.update(loaded_tokens)

    # pending
    loaded_pending = _load_json_or_default(path=PENDING_PATH, default=[])
    dq = deque(maxlen=BUFFER_MAX)
    if isinstance(loaded_pending, list):
        dq.extend(loaded_pending[:BUFFER_MAX])
    #Removes all existing key–value pairs from the global "pending" deque
    pending.clear()
    #Update the global "pending" deque with the loaded data
    pending.extend(dq)

# --- Startup hook ---
@app.on_event("startup")
#“Running when the application starts, before handling any incoming HTTP request
def _startup_load_from_disk():
    _ensure_persist_dir()
    load_all()


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

    now = int(time.time())
    # get the expiration timestamp from the item, if not found, use 0
    expires_at = int(item.get("expires_at", 0))

    # Refresh if expiring within 60s
    if now >= expires_at - 60:
        refresh_token = item.get("refresh_token")
        if not refresh_token:
            # Can't refresh; return as-is (caller may re-auth if 401 later)
            return item

        # refresh the tokens using the refresh_token from the item
        refreshed = await refresh_with_refresh_token(refresh_token)
        tokens[state] = {
            "access_token": refreshed["access_token"],
            "refresh_token": refreshed.get("refresh_token", refresh_token),  # HH may rotate or not
            "token_type": refreshed.get("token_type", "Bearer"),
            "expires_in": refreshed.get("expires_in"),
            "expires_at": refreshed["expires_at"],
        }
        # save the updated tokens to disk
        save_tokens()
        # update the item in memory with the refreshed tokens
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


@app.get("/")
# Health check endpoint to verify the service is running
def health():
    return PlainTextResponse("Endpoint is available")


@app.get("/hh/callback")
# HH redirect target: /hh/callback?code=...&state=...
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
    # add the item to the pending deque in memory buffer
    pending.append(item)
    # save the pending data to disk
    save_pending()

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
        # save the updated tokens to disk
        save_tokens()
        return PlainTextResponse("Вы успешно авторизовались в HH.ru, можете вернуться в Telegram")
    except httpx.HTTPError as e:
        # keep the pending record, but don’t store tokens
        return PlainTextResponse(f"Ошибка авторизации: {str(e)}", status_code=500)



@app.post("/token/by-state")
# Bot → Render: return a valid access token for a given state (refreshing if needed)
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



@app.delete("/admin/state")
# Optional: one-shot dequeue/cleanup after you’ve stored the mapping user ↔ tokens elsewhere
# payload: StatePayload -> comes from the request body (JSON)
# authorization: Optional[str] = Header(None) -> FastAPI automatically maps that HTTP header to the Python parameter "admin_token".
def admin_delete_state(payload: StatePayload, admin_token: Optional[str] = Header(None)):
    #check ADMIN_TOKEN in the authorization header
    require_admin(admin_token)
    #using .pop() method remove the item with key "state" and returns its value. 
    #if key is not found, returns default (None)
    existed = tokens.pop(payload.state, None)
    # save the updated tokens to disk
    save_tokens()
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
