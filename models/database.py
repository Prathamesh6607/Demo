import sqlite3
import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from device_models import IoTDevice, DeviceStatus, RiskLevel

class DeviceDatabase:
    def __init__(self, db_path: str = "iot_devices.db"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database with enhanced schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Enhanced network devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_name TEXT,
                mac_address TEXT UNIQUE,
                ip_address TEXT,
                manufacturer TEXT,
                device_type TEXT,
                device_model TEXT,
                firmware_version TEXT,
                os_version TEXT,
                protocols TEXT,
                status TEXT,
                risk_score INTEGER DEFAULT 0,
                open_ports TEXT,
                services TEXT,
                cves TEXT,
                dhcp_fingerprint TEXT,
                mdns_services TEXT,
                tls_cert_info TEXT,
                communication_partners TEXT,
                data_usage TEXT,
                tags TEXT,
                last_seen TIMESTAMP,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_quarantined BOOLEAN DEFAULT FALSE,
                last_risk_assessment TIMESTAMP
            )
        ''')
        
        # Bluetooth devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS bluetooth_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_name TEXT,
                mac_address TEXT UNIQUE,
                device_type TEXT,
                rssi INTEGER,
                services TEXT,
                last_seen TIMESTAMP,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Device vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS device_vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_mac TEXT,
                cve_id TEXT,
                severity TEXT,
                cvss_score REAL,
                description TEXT,
                published_date TIMESTAMP,
                FOREIGN KEY (device_mac) REFERENCES network_devices (mac_address)
            )
        ''')
        
        # Network traffic logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                port INTEGER,
                bytes_sent INTEGER,
                bytes_received INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_network_devices_mac ON network_devices(mac_address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_network_devices_ip ON network_devices(ip_address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_network_devices_risk ON network_devices(risk_score)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulnerabilities_device ON device_vulnerabilities(device_mac)')
        
        conn.commit()
        conn.close()
    
    def save_network_device(self, device: IoTDevice) -> bool:
        """Save enhanced network device to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            device_dict = device.to_dict()
            
            cursor.execute('''
                INSERT OR REPLACE INTO network_devices 
                (device_name, mac_address, ip_address, manufacturer, device_type,
                 device_model, firmware_version, os_version, protocols, status,
                 risk_score, open_ports, services, cves, dhcp_fingerprint,
                 mdns_services, tls_cert_info, communication_partners, data_usage,
                 tags, last_seen, is_quarantined, last_risk_assessment)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                device_dict.get('device_name'),
                device_dict.get('mac_address'),
                device_dict.get('ip_address'),
                device_dict.get('manufacturer'),
                device_dict.get('device_type'),
                device_dict.get('device_model'),
                device_dict.get('firmware_version'),
                device_dict.get('os_version'),
                json.dumps(device_dict.get('protocols', [])),
                device_dict.get('status'),
                device_dict.get('risk_score', 0),
                json.dumps(device_dict.get('open_ports', [])),
                json.dumps(device_dict.get('services', [])),
                json.dumps(device_dict.get('cves', [])),
                device_dict.get('dhcp_fingerprint'),
                json.dumps(device_dict.get('mdns_services', [])),
                json.dumps(device_dict.get('tls_cert_info', {})),
                json.dumps(device_dict.get('communication_partners', [])),
                json.dumps(device_dict.get('data_usage', {})),
                json.dumps(device_dict.get('tags', [])),
                device_dict.get('last_seen'),
                device.status == DeviceStatus.QUARANTINED,
                datetime.now().isoformat() if device_dict.get('risk_score', 0) > 0 else None
            ))
            
            # Save vulnerabilities separately
            for cve in device.cves:
                cursor.execute('''
                    INSERT OR IGNORE INTO device_vulnerabilities 
                    (device_mac, cve_id, severity, cvss_score, description, published_date)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    device.mac_address,
                    cve,
                    'Unknown',  # Would be populated from CVE database
                    0.0,        # Would be populated from CVE database
                    '',         # Would be populated from CVE database
                    datetime.now().isoformat()
                ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error saving network device: {e}")
            return False
    
    def save_bluetooth_device(self, device: Dict[str, Any]) -> bool:
        """Save Bluetooth device to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO bluetooth_devices 
                (device_name, mac_address, device_type, rssi, services, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                device.get('name'),
                device.get('mac_address'),
                device.get('device_type'),
                device.get('rssi'),
                json.dumps(device.get('services', [])),
                device.get('last_seen', 'Unknown')
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error saving Bluetooth device: {e}")
            return False
    
    def get_network_devices(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Get all network devices with optional filtering"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = 'SELECT * FROM network_devices'
            params = []
            
            if filters:
                where_clauses = []
                for key, value in filters.items():
                    if key == 'risk_level':
                        if value == 'Critical':
                            where_clauses.append('risk_score >= 800')
                        elif value == 'High':
                            where_clauses.append('risk_score >= 600 AND risk_score < 800')
                        elif value == 'Medium':
                            where_clauses.append('risk_score >= 400 AND risk_score < 600')
                        elif value == 'Low':
                            where_clauses.append('risk_score < 400')
                    elif key == 'status':
                        where_clauses.append('status = ?')
                        params.append(value)
                    elif key == 'device_type':
                        where_clauses.append('device_type = ?')
                        params.append(value)
                    elif key == 'manufacturer':
                        where_clauses.append('manufacturer LIKE ?')
                        params.append(f'%{value}%')
                
                if where_clauses:
                    query += ' WHERE ' + ' AND '.join(where_clauses)
            
            query += ' ORDER BY risk_score DESC, last_seen DESC'
            cursor.execute(query, params)
            
            devices = []
            for row in cursor.fetchall():
                device = dict(row)
                # Parse JSON fields
                device['protocols'] = json.loads(device['protocols']) if device['protocols'] else []
                device['open_ports'] = json.loads(device['open_ports']) if device['open_ports'] else []
                device['services'] = json.loads(device['services']) if device['services'] else []
                device['cves'] = json.loads(device['cves']) if device['cves'] else []
                device['mdns_services'] = json.loads(device['mdns_services']) if device['mdns_services'] else []
                device['tls_cert_info'] = json.loads(device['tls_cert_info']) if device['tls_cert_info'] else {}
                device['communication_partners'] = json.loads(device['communication_partners']) if device['communication_partners'] else []
                device['data_usage'] = json.loads(device['data_usage']) if device['data_usage'] else {}
                device['tags'] = json.loads(device['tags']) if device['tags'] else []
                
                # Calculate risk level
                risk_score = device.get('risk_score', 0)
                if risk_score >= 800:
                    device['risk_level'] = 'Critical'
                elif risk_score >= 600:
                    device['risk_level'] = 'High'
                elif risk_score >= 400:
                    device['risk_level'] = 'Medium'
                else:
                    device['risk_level'] = 'Low'
                
                devices.append(device)
            
            conn.close()
            return devices
            
        except Exception as e:
            print(f"Error getting network devices: {e}")
            return []
    
    def get_device_by_mac(self, mac_address: str) -> Optional[Dict[str, Any]]:
        """Get a specific device by MAC address"""
        devices = self.get_network_devices()
        for device in devices:
            if device['mac_address'] == mac_address:
                return device
        return None
    
    def get_bluetooth_devices(self) -> List[Dict[str, Any]]:
        """Get all Bluetooth devices"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM bluetooth_devices ORDER BY last_seen DESC')
            devices = []
            for row in cursor.fetchall():
                device = dict(row)
                device['services'] = json.loads(device['services']) if device['services'] else []
                devices.append(device)
            
            conn.close()
            return devices
            
        except Exception as e:
            print(f"Error getting Bluetooth devices: {e}")
            return []
    
    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get enhanced dashboard statistics"""
        try:
            network_devices = self.get_network_devices()
            
            # Calculate risk statistics
            critical_devices = len([d for d in network_devices if d.get('risk_level') == 'Critical'])
            high_risk_devices = len([d for d in network_devices if d.get('risk_level') in ['Critical', 'High']])
            
            # Count devices with vulnerabilities
            devices_with_vulns = len([d for d in network_devices if d.get('cves')])
            
            # Count total open ports
            total_open_ports = sum(len(d.get('open_ports', [])) for d in network_devices)
            
            return {
                'total_devices': len(network_devices),
                'active_devices': len([d for d in network_devices if d.get('status') == 'Active']),
                'inactive_devices': len([d for d in network_devices if d.get('status') == 'Inactive']),
                'critical_devices': critical_devices,
                'high_risk_devices': high_risk_devices,
                'devices_with_vulnerabilities': devices_with_vulns,
                'total_open_ports': total_open_ports,
                'device_types': len(set(d.get('device_type') for d in network_devices)),
                'quarantined_devices': len([d for d in network_devices if d.get('status') == 'Quarantined'])
            }
        except Exception as e:
            print(f"Error getting dashboard stats: {e}")
            return {
                'total_devices': 0,
                'active_devices': 0,
                'inactive_devices': 0,
                'critical_devices': 0,
                'high_risk_devices': 0,
                'devices_with_vulnerabilities': 0,
                'total_open_ports': 0,
                'device_types': 0,
                'quarantined_devices': 0
            }
    
    def get_combined_devices(self) -> List[Dict[str, Any]]:
        """Get combined devices for dashboard"""
        network_devices = self.get_network_devices()
        bluetooth_devices = self.get_bluetooth_devices()
        return network_devices + bluetooth_devices
    
    def update_device_risk_score(self, mac_address: str, risk_score: int) -> bool:
        """Update risk score for a device"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE network_devices 
                SET risk_score = ?, last_risk_assessment = ?
                WHERE mac_address = ?
            ''', (risk_score, datetime.now().isoformat(), mac_address))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error updating risk score: {e}")
            return False
    
    def quarantine_device(self, mac_address: str) -> bool:
        """Quarantine a device"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE network_devices 
                SET status = ?, is_quarantined = ?
                WHERE mac_address = ?
            ''', (DeviceStatus.QUARANTINED.value, True, mac_address))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error quarantining device: {e}")
            return False
    
    def get_vulnerabilities_by_device(self, mac_address: str) -> List[Dict[str, Any]]:
        """Get vulnerabilities for a specific device"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM device_vulnerabilities 
                WHERE device_mac = ?
                ORDER BY cvss_score DESC
            ''', (mac_address,))
            
            vulnerabilities = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return vulnerabilities
            
        except Exception as e:
            print(f"Error getting vulnerabilities: {e}")
            return []
    
    def log_network_traffic(self, traffic_data: Dict[str, Any]) -> bool:
        """Log network traffic data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO network_traffic 
                (source_ip, destination_ip, protocol, port, bytes_sent, bytes_received)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                traffic_data.get('source_ip'),
                traffic_data.get('destination_ip'),
                traffic_data.get('protocol'),
                traffic_data.get('port'),
                traffic_data.get('bytes_sent', 0),
                traffic_data.get('bytes_received', 0)
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error logging network traffic: {e}")
            return False