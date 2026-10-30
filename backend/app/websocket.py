import json
from typing import Dict, Any, Optional
from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        # Maps WebSocket connection to user metadata dict {"role": str, "username": str}
        self.active_connections: Dict[WebSocket, Dict[str, Any]] = {}

    async def connect(self, websocket: WebSocket, user_meta: Optional[Dict[str, Any]] = None):
        await websocket.accept()
        self.active_connections[websocket] = user_meta or {"role": "viewer", "username": "anonymous"}

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            del self.active_connections[websocket]

    async def broadcast_event(self, event_data: dict):
        disconnected = []
        for connection, user_meta in list(self.active_connections.items()):
            try:
                # Sensitive honeypot credentials protection:
                # Mask passwords for non-admin viewers to satisfy security hardening requirements
                payload = dict(event_data)
                if user_meta.get("role") != "admin" and payload.get("password"):
                    payload["password"] = "****** (redacted)"

                data_str = json.dumps(payload, default=str)
                await connection.send_text(data_str)
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            self.disconnect(conn)

    async def broadcast_alert(self, alert_data: dict):
        disconnected = []
        message = {
            "type": "SECURITY_ALERT",
            "alert": alert_data
        }
        data_str = json.dumps(message, default=str)
        for connection in list(self.active_connections.keys()):
            try:
                await connection.send_text(data_str)
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            self.disconnect(conn)

manager = ConnectionManager()
