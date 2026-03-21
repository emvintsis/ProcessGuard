from fastapi import FastAPI

app = FastAPI() # fastapi class import

@app.post("/api/v1/telemetry/batch") # new instance of app

def receive_telemetry(data: dict):
    print(data)
    return {"status": "ok"}

