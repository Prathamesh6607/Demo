from typing import List, Dict, Any
from datetime import datetime

class BluetoothScanner:
    def __init__(self):
        self.discovered_devices = []
        self.is_scanning = False

    def scan_bluetooth(self, duration: int = 30) -> List[Dict[str, Any]]:
        """Scan for classic Bluetooth devices using pybluez, returning address and name."""
        self.is_scanning = True
        self.discovered_devices = []
        try:
            import bluetooth
            print("Looking for bluetooth devices ..........")
            devices = bluetooth.discover_devices(duration=duration, lookup_names=True)
            for addr, name in devices:
                print("Address :", addr)
                print("Name :", name)
                self.discovered_devices.append({
                    "name": name or "Unknown",
                    "mac_address": addr,
                    "device_type": "classic",
                    "rssi": None,
                    "services": [],
                    "last_seen": datetime.now().isoformat()
                })
        except Exception as e:
            print(f"Classic Bluetooth scan failed: {e}")
        self.is_scanning = False
        return self.discovered_devices

    def get_scan_progress(self) -> Dict[str, Any]:
        return {
            "status": "scanning" if self.is_scanning else "completed",
            "current_operation": "Scanning for Bluetooth devices",
            "devices_found": len(self.discovered_devices)
        }

    def stop_scan(self):
        self.is_scanning = False