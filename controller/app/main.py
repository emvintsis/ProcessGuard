from fastapi import FastAPI
from pydantic import BaseModel
import uuid

class AgentRegister(BaseModel):
    hostname: str
    ip: str
    mac: str
    username: str

app = FastAPI() # fastapi class import

agents = {}

@app.post("/api/v1/agents/register")

def register_agent(data: AgentRegister):
    agent_id = None
    if data.hostname in agents:
        agent_id = agents[data.hostname]["agent_id"]
    else:
        agent_id = str(uuid.uuid4())
    
    agents[data.hostname] = {"agent_id": agent_id,
                                "hostname": data.hostname,
                                 "ip": data.ip,
                                 "mac": data.mac,
                                 "username": data.username}
    return {"agent_id": agent_id}

@app.post("/api/v1/telemetry/batch") # new instance of app

def receive_telemetry(data: dict):
    print(data)
    return {"status": "ok"}

