"""
from fastapi import FastAPI, Request
app = FastAPI()

#Defines a GET endpoint at /hh/callback using the @app.get() decorator
@app.get("/hh/callback")
#Defines an async function that accepts a Request object as an argument
async def callback(request: Request):
    #Extracts the code and state parameters from the query string of the incoming request
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    #Returns a dictionary with the code and state parameters
    return {"code": code, "state": state}
"""



# main.py
import os, time, json
from collections import deque
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import PlainTextResponse, JSONResponse

app = FastAPI()

ADMIN_TOKEN   = os.getenv("ADMIN_TOKEN")     # simple auth for pull endpoints

# every item exceeding the buffer max will be removed from memory using FIFO.
# Data is lost on restart (no database)
BUFFER_MAX = 100
pending = deque(maxlen=BUFFER_MAX)

# Health check endpoint to verify the service is running
@app.get("/")
def health():
    return PlainTextResponse("Endpoint is available")

# Record data from HH redirections 
@app.get("/hh/callback")
async def hh_callback(request: Request):
    code  = request.query_params.get("code")
    state = request.query_params.get("state")
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code/state")
    # Create a new item with the code, state, timestamp, and IP address
    item = {
        "state": state,
        "code": code,
        "ts": int(time.time()),
        "ip": request.client.host if request.client else None,
    }
    pending.append(item)

    # show minimal OK page to the user
    return PlainTextResponse("Authorization received. You can return to Telegram now.")

# Pull: list all pending (requires admin token)
@app.get("/admin/pending")
def admin_pending(admin_token: str):
    if admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return JSONResponse(list(pending))

# Remove item from memoryby state
@app.get("/admin/dequeue")
def admin_dequeue(admin_token: str, state: str):
    if admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not state:
        raise HTTPException(status_code=400, detail="Missing state parameter")
    
    # find & remove the first matching item
    for item in pending:
        if item["state"] == state:
            pending.remove(item)
            return PlainTextResponse(f"Data for state {state} has been removed: {json.dumps(item)}")
    
    raise HTTPException(status_code=404, detail="State not found in queue")
