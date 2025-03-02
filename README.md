# TETREX_AB2_05
RANSOMEWARE EARLY DETECTION AND RESPONSE SYSTEM 
# Advanced Ransomware Monitoring API

A FastAPI-based system for real-time ransomware monitoring with a dynamic HTML/CSS/JavaScript dashboard for live alerts and system metrics.

## Features

- **Real-Time Monitoring:** Tracks CPU, memory, disk, and file events.
- **Anomaly Detection:** Detects potential ransomware activity.
- **Live Alerts:** Uses WebSockets for immediate notifications.
- **Simulation Endpoint:** Trigger a test ransomware simulation.

## Project Structure

project-root/ ├── backend/ │ ├── app/ │ │ ├── main.py # FastAPI entry point │ │ ├── routes.py # API endpoints & WebSocket routes │ │ └── utils.py # Utility functions & monitoring logic │ └── requirements.txt # Python dependencies ├── frontend/ │ ├── index.html # Dashboard HTML │ ├── styles.css # Styling │ └── script.js # JavaScript for API communication ├── docs/ # Documentation ├── README.md # This file └── LICENSE # License information

API Endpoints
GET /system_data: Returns current system metrics and detection status.
GET /simulate_ransomware: Triggers a ransomware simulation.
WebSocket /ws/alerts?token=mysecrettoken: Provides live alerts.
