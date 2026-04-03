from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import uuid

app = FastAPI() # fastapi class import

agents = {} # agents dictionnary, will receive informations about agent owners

class AgentRegister(BaseModel):
    hostname: str
    ip: str
    mac: str
    username: str

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

websocket_connections = {}

@app.websocket("/ws/agent/{agent_id}")
async def websocket_endpoint(agent_id: str, websocket: WebSocket):
    await websocket.accept()
    websocket_connections[agent_id] = websocket

    while True:
        try:
            data = await websocket.receive_text()
        except WebSocketDisconnect:
            del websocket_connections[agent_id]

@app.post("/api/v1/telemetry/batch") # new instance of app
def receive_telemetry(data: dict):
    print(data)
    return {"status": "ok"}

