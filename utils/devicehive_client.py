from typing import List, Dict, Any

class DeviceHiveClient:
    def connect(self, server_url: str, access_token: str) -> bool:
        """Connect to DeviceHive"""
        print(f"Connecting to DeviceHive at {server_url}")
        return True
    
    def get_devices(self) -> List[Dict[str, Any]]:
        """Get devices from DeviceHive"""
        # Return simulated devices for demo
        return [
            {
                "id": "thermostat-001",
                "name": "Smart Thermostat",
                "status": "online",
                "type": "sensor"
            },
            {
                "id": "camera-001", 
                "name": "Security Camera",
                "status": "online",
                "type": "camera"
            },
            {
                "id": "lock-001",
                "name": "Smart Lock", 
                "status": "offline",
                "type": "lock"
            }
        ]
    
    def start_monitoring(self, device_id: str) -> Dict[str, Any]:
        """Start monitoring a device"""
        return {
            "device_id": device_id,
            "status": "monitoring",
            "data": {
                "temperature": 22.5,
                "humidity": 45.0,
                "timestamp": "2024-01-01T12:00:00Z"
            }
        }