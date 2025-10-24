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