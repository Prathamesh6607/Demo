import json
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
import threading

from models.device_models import IoTDevice, DeviceStatus, DeviceType, Protocol, RiskLevel
from utils.database import DeviceDatabase

logger = logging.getLogger(__name__)

class AssetInventory:
    def __init__(self, db_path: str = "iot_devices.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self.database = DeviceDatabase(db_path)
    
    def add_device(self, device: IoTDevice) -> bool:
        """Add a new device to the inventory using enhanced database"""
        try:
            return self.database.save_network_device(device)
        except Exception as e:
            logger.error(f"Error adding device: {e}")
            return False
    
    def add_devices_batch(self, devices: List[IoTDevice]) -> bool:
        """Add multiple devices in batch"""
        try:
            success_count = 0
            for device in devices:
                if self.add_device(device):
                    success_count += 1
            
            logger.info(f"Added {success_count}/{len(devices)} devices to inventory")
            return success_count == len(devices)
                
        except Exception as e:
            logger.error(f"Error adding devices batch: {e}")
            return False
    
    def get_all_devices(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Retrieve all devices from inventory with optional filtering"""
        try:
            return self.database.get_network_devices(filters)
        except Exception as e:
            logger.error(f"Error retrieving devices: {e}")
            return []
    
    def get_device_by_mac(self, mac_address: str) -> Optional[Dict[str, Any]]:
        """Get device by MAC address"""
        try:
            return self.database.get_device_by_mac(mac_address)
        except Exception as e:
            logger.error(f"Error retrieving device: {e}")
            return None
    
    def get_devices_by_risk_level(self, risk_level: str) -> List[Dict[str, Any]]:
        """Get devices by risk level"""
        filters = {'risk_level': risk_level}
        return self.get_all_devices(filters)
    
    def get_high_risk_devices(self) -> List[Dict[str, Any]]:
        """Get high and critical risk devices"""
        high_risk = self.get_devices_by_risk_level('High')
        critical_risk = self.get_devices_by_risk_level('Critical')
        return high_risk + critical_risk
    
    def update_device_status(self, mac_address: str, status: DeviceStatus) -> bool:
        """Update device status"""
        try:
            device = self.get_device_by_mac(mac_address)
            if device:
                # Create IoTDevice object for update
                iot_device = self._dict_to_iot_device(device)
                iot_device.status = status
                return self.add_device(iot_device)
            return False
        except Exception as e:
            logger.error(f"Error updating device status: {e}")
            return False
    
    def quarantine_device(self, mac_address: str) -> bool:
        """Quarantine a device"""
        try:
            return self.database.quarantine_device(mac_address)
        except Exception as e:
            logger.error(f"Error quarantining device: {e}")
            return False
    
    def update_device_risk_score(self, mac_address: str, risk_score: int) -> bool:
        """Update device risk score"""
        try:
            return self.database.update_device_risk_score(mac_address, risk_score)
        except Exception as e:
            logger.error(f"Error updating risk score: {e}")
            return False
    
    def add_device_vulnerability(self, mac_address: str, cve_id: str, severity: str = "Unknown", 
                               cvss_score: float = 0.0, description: str = "") -> bool:
        """Add vulnerability to device"""
        try:
            device = self.get_device_by_mac(mac_address)
            if device:
                iot_device = self._dict_to_iot_device(device)
                iot_device.add_cve(cve_id)
                return self.add_device(iot_device)
            return False
        except Exception as e:
            logger.error(f"Error adding vulnerability: {e}")
            return False
    
    def get_device_vulnerabilities(self, mac_address: str) -> List[Dict[str, Any]]:
        """Get vulnerabilities for a specific device"""
        try:
            return self.database.get_vulnerabilities_by_device(mac_address)
        except Exception as e:
            logger.error(f"Error getting vulnerabilities: {e}")
            return []
    
    def delete_device(self, mac_address: str) -> bool:
        """Delete device from inventory"""
        try:
            # Note: This would need to be implemented in the database class
            # For now, using the basic implementation
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('DELETE FROM network_devices WHERE mac_address = ?', (mac_address,))
                
                conn.commit()
                conn.close()
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Error deleting device: {e}")
            return False
    
    def get_devices_by_status(self, status: DeviceStatus) -> List[Dict[str, Any]]:
        """Get devices by status"""
        filters = {'status': status.value}
        return self.get_all_devices(filters)
    
    def get_devices_by_type(self, device_type: str) -> List[Dict[str, Any]]:
        """Get devices by type"""
        filters = {'device_type': device_type}
        return self.get_all_devices(filters)
    
    def search_devices(self, query: str) -> List[Dict[str, Any]]:
        """Search devices by name, manufacturer, or IP"""
        all_devices = self.get_all_devices()
        query_lower = query.lower()
        
        return [
            device for device in all_devices
            if (query_lower in device.get('device_name', '').lower() or
                query_lower in device.get('manufacturer', '').lower() or
                query_lower in device.get('ip_address', '').lower() or
                query_lower in device.get('device_model', '').lower())
        ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get enhanced inventory statistics"""
        try:
            return self.database.get_dashboard_stats()
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return self._get_basic_statistics()
    
    def _get_basic_statistics(self) -> Dict[str, Any]:
        """Fallback basic statistics"""
        devices = self.get_all_devices()
        
        total_devices = len(devices)
        active_devices = len([d for d in devices if d.get('status') == DeviceStatus.ACTIVE.value])
        inactive_devices = len([d for d in devices if d.get('status') == DeviceStatus.INACTIVE.value])
        
        device_type_count = {}
        for device in devices:
            dev_type = device.get('device_type', 'Unknown')
            device_type_count[dev_type] = device_type_count.get(dev_type, 0) + 1
        
        return {
            "total_devices": total_devices,
            "active_devices": active_devices,
            "inactive_devices": inactive_devices,
            "device_type_distribution": device_type_count,
            "critical_devices": 0,
            "high_risk_devices": 0,
            "devices_with_vulnerabilities": 0,
            "total_open_ports": 0,
            "quarantined_devices": 0
        }
    
    def get_risk_distribution(self) -> Dict[str, int]:
        """Get distribution of devices by risk level"""
        devices = self.get_all_devices()
        
        distribution = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        
        for device in devices:
            risk_level = device.get('risk_level', 'Low')
            distribution[risk_level] = distribution.get(risk_level, 0) + 1
        
        return distribution
    
    def get_recent_devices(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get devices seen in the last specified hours"""
        all_devices = self.get_all_devices()
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        recent_devices = []
        for device in all_devices:
            last_seen_str = device.get('last_seen')
            if last_seen_str:
                try:
                    last_seen = datetime.fromisoformat(last_seen_str.replace('Z', '+00:00'))
                    if last_seen >= cutoff_time:
                        recent_devices.append(device)
                except ValueError:
                    continue
        
        return recent_devices
    
    def export_devices(self, format_type: str = "json") -> Optional[str]:
        """Export devices to various formats"""
        devices = self.get_all_devices()
        
        if format_type == "json":
            return json.dumps(devices, indent=2)
        elif format_type == "csv":
            # Simple CSV export
            if not devices:
                return ""
            
            headers = devices[0].keys()
            csv_lines = [','.join(headers)]
            for device in devices:
                row = [str(device.get(header, '')) for header in headers]
                csv_lines.append(','.join(row))
            
            return '\n'.join(csv_lines)
        
        return None
    
    def _dict_to_iot_device(self, device_dict: Dict[str, Any]) -> IoTDevice:
        """Convert dictionary to IoTDevice object"""
        protocols = [Protocol(p) for p in device_dict.get('protocols', [])]
        
        return IoTDevice(
            device_name=device_dict.get('device_name', ''),
            mac_address=device_dict.get('mac_address', ''),
            ip_address=device_dict.get('ip_address', ''),
            manufacturer=device_dict.get('manufacturer', ''),
            device_type=DeviceType(device_dict.get('device_type', DeviceType.OTHER.value)),
            firmware_version=device_dict.get('firmware_version', 'Unknown'),
            protocols=protocols,
            last_seen=datetime.fromisoformat(device_dict.get('last_seen').replace('Z', '+00:00')),
            status=DeviceStatus(device_dict.get('status', DeviceStatus.UNKNOWN.value)),
            risk_score=device_dict.get('risk_score', 0),
            open_ports=device_dict.get('open_ports', []),
            services=device_dict.get('services', []),
            cves=device_dict.get('cves', []),
            device_model=device_dict.get('device_model'),
            os_version=device_dict.get('os_version')
        )
    
    def cleanup_old_devices(self, days: int = 30) -> int:
        """Remove devices not seen in specified days"""
        try:
            cutoff_time = datetime.now() - timedelta(days=days)
            cutoff_iso = cutoff_time.isoformat()
            
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('DELETE FROM network_devices WHERE last_seen < ?', (cutoff_iso,))
                deleted_count = cursor.rowcount
                
                conn.commit()
                conn.close()
                
                logger.info(f"Cleaned up {deleted_count} devices older than {days} days")
                return deleted_count
                
        except Exception as e:
            logger.error(f"Error cleaning up old devices: {e}")
            return 0