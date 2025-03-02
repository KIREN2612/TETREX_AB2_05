from fastapi import APIRouter, WebSocket, Query, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import threading
import asyncio

# Import functions and globals from utils.py
from utils import (
    collect_and_predict,
    simulate_ransomware,
    connected_clients,
    ensemble_models
)

router = APIRouter()
templates = Jinja2Templates(directory="joo")  # Adjust the directory as needed

@router.websocket("/ws/alerts")
async def websocket_alert_endpoint(websocket: WebSocket, token: str = Query(...)):
    # Verify token (API key)
    if token != "mysecrettoken":
        await websocket.close(code=1008)
        raise HTTPException(status_code=403, detail="Unauthorized")
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            # Wait for incoming messages (if needed)
            await websocket.receive_text()
    except Exception:
        # Catch any exception (or WebSocketDisconnect) and proceed
        pass
    finally:
        if websocket in connected_clients:
            connected_clients.remove(websocket)

@router.get("/", summary="Welcome")
def read_root():
    return {"message": "Welcome to the Advanced Ransomware Monitoring API. Live tracking is active."}

@router.get("/system_data", summary="Get a Snapshot of System Data and Detection")
def get_system_data():
    data = collect_and_predict(ensemble_models)
    return {
        "status": data.get("state"),
        "ml_model_dedicated": data.get("ml_model_dedicated"),
        "data": data
    }

@router.get("/dashboard", response_class=HTMLResponse, summary="Dashboard")
def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@router.get("/simulate_ransomware", summary="Simulate a Ransomware Attack")
def simulate_ransomware_endpoint():
    threading.Thread(target=simulate_ransomware, daemon=True).start()
    return {"message": "Simulated ransomware attack triggered."}
