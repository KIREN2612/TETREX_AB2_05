from fastapi import FastAPI
from routes import router as api_router
import threading
import asyncio
from utils import FileMonitorHandler, start_file_monitor, MONITOR_PATH

app = FastAPI(title="Advanced Ransomware Monitoring API")
app.include_router(api_router)

@app.on_event("startup")
async def startup_event():
    # Initialize file monitor
    global file_monitor_handler_global, ensemble_models, main_loop
    from utils import file_monitor_handler_global  # if needed
    file_monitor_handler_global = FileMonitorHandler()
    threading.Thread(target=start_file_monitor, args=(MONITOR_PATH, file_monitor_handler_global), daemon=True).start()
    
    ensemble_models = None  # Update if you load models
    main_loop = asyncio.get_running_loop()
    asyncio.create_task(asyncio.sleep(0))  # Placeholder to start async tasks if needed

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
