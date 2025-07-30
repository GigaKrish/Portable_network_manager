# FILE: web/api.py
# PURPOSE: Contains the FastAPI web server and all API endpoints.
#Upgraded from Flask API to asynchronous Fast API


import json
import asyncio
import psutil
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from core.data_models import (
    data_lock, ip_traffic, process_traffic, packet_rate_history, selected_interface
)

class ConnectionManager:
    def __init__(self): self.active_connections = []
    async def connect(self, websocket): await websocket.accept(); self.active_connections.append(websocket)
    def disconnect(self, websocket):
        if websocket in self.active_connections: self.active_connections.remove(websocket)
    async def broadcast(self, message):
        for connection in self.active_connections[:]:
            try: await connection.send_text(message)
            except Exception: self.disconnect(connection)

manager = ConnectionManager()

async def broadcast_data():
    while True:
        with data_lock:
            sorted_ips = sorted(ip_traffic.items(), key=lambda item: item[1]['in_count'] + item[1]['out_count'], reverse=True)
            top_talkers = [{'ip': ip, **data} for ip, data in sorted_ips[:30]]
            sorted_pids = sorted(process_traffic.keys(), key=lambda pid: process_traffic[pid]['in_count'] + process_traffic[pid]['out_count'], reverse=True)
            processes = [{'pid': pid, **process_traffic[pid]} for pid in sorted_pids[:30]]
            payload = {'type': 'update', 'interface': selected_interface, 'packet_rate': list(packet_rate_history), 'top_talkers': top_talkers, 'processes': processes}
        await manager.broadcast(json.dumps(payload))
        await asyncio.sleep(2)

@asynccontextmanager
async def lifespan(app: FastAPI):
    asyncio.create_task(broadcast_data())
    yield

app = FastAPI(lifespan=lifespan)

@app.get("/", response_class=HTMLResponse)
async def get_root():
    with open("web/static/index.html") as f:
        return HTMLResponse(content=f.read())

@app.post("/api/process/{pid}/terminate", response_class=JSONResponse)
async def api_terminate_process(pid: int):
    try:
        p = psutil.Process(pid)
        p.terminate()
        return {"status": "success", "message": f"Termination signal sent to process {pid} ({p.name()})."}
    except psutil.NoSuchProcess: raise HTTPException(404, "Process not found.")
    except psutil.AccessDenied: raise HTTPException(403, "Access denied.")
    except Exception as e: raise HTTPException(500, str(e))

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True: await websocket.receive_text()
    except WebSocketDisconnect: manager.disconnect(websocket)
