import subprocess
import re
import logging
import socket
import threading
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
from urllib.parse import urlparse
import requests

from models.device_models import IoTDevice, DeviceStatus, DeviceType, Protocol, RiskLevel

logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self):
        self.is_scanning = False
        self.scan_progress = {
            'status': 'idle',
            'current_operation': 'Ready to scan',
            'devices_found': 0,
            'current_device': None
        }
        self.passive_scanner = PassiveFingerprinter()
    
    def comprehensive_scan(self, network_range: str = "192.168.1.0/24") -> Dict[str, Any]:
        """
        Perform comprehensive network scan with enhanced device identification
        """
        self.is_scanning = True
        self.scan_progress = {
            'status': 'scanning',
            'current_operation': f'Starting comprehensive scan of {network_range}',
            'devices_found': 0,
            'current_device': None
        }
        
        discovered_devices = []
        
        try:
            # Step 1: Passive fingerprinting
            self.scan_progress['current_operation'] = 'Performing passive fingerprinting'
            passive_devices = self.passive_scanner.scan()
            discovered_devices.extend(passive_devices)
            
            # Step 2: Active nmap scan
            self.scan_progress['current_operation'] = 'Performing active network discovery'
            active_devices = self._perform_nmap_scan(network_range)
            
            # Merge devices (prioritize passive data)
            for active_device in active_devices:
                existing_device = next((d for d in discovered_devices if d.mac_address == active_device.mac_address), None)
                if not existing_device:
                    discovered_devices.append(active_device)
                else:
                    # Enhance existing device with active scan data
                    if existing_device.ip_address == "Unknown" and active_device.ip_address != "Unknown":
                        existing_device.ip_address = active_device.ip_address
            
            # Step 3: Enhanced service discovery for each device
            self.scan_progress['current_operation'] = 'Performing service discovery'
            for i, device in enumerate(discovered_devices):
                if device.ip_address and device.ip_address != "Unknown":
                    self.scan_progress['current_device'] = f"{device.device_name} ({device.ip_address})"
                    enhanced_device = self._enhance_device_discovery(device)
                    discovered_devices[i] = enhanced_device
            
            # Step 4: Vulnerability assessment
            self.scan_progress['current_operation'] = 'Assessing device vulnerabilities'
            for i, device in enumerate(discovered_devices):
                device_with_risk = self._assess_device_risk(device)
                discovered_devices[i] = device_with_risk
            
            self.is_scanning = False
            self.scan_progress = {
                'status': 'completed',
                'current_operation': 'Scan completed',
                'devices_found': len(discovered_devices),
                'current_device': None
            }
            
            return {
                'success': True,
                'devices': [device.to_dict() for device in discovered_devices],
                'total_devices': len(discovered_devices),
                'scan_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Comprehensive network scan failed: {e}")
            self.is_scanning = False
            return {'error': f'Network scan failed: {str(e)}'}
    
    def _perform_nmap_scan(self, network_range: str) -> List[IoTDevice]:
        """Perform detailed nmap scan with service detection"""
        devices = []
        
        try:
            # First: Host discovery
            result = subprocess.run(
                ['nmap', '-sn', network_range],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                basic_devices = self._parse_nmap_output(result.stdout)
                
                # Enhanced scan for each discovered device
                for basic_info in basic_devices:
                    if basic_info['ip_address'] != "Unknown":
                        enhanced_info = self._scan_device_services(basic_info['ip_address'])
                        device = self._create_iot_device({**basic_info, **enhanced_info})
                        devices.append(device)
            
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
        
        return devices
    
    def _scan_device_services(self, ip_address: str) -> Dict[str, Any]:
        """Perform service detection on a specific device"""
        services = []
        open_ports = []
        
        try:
            # Scan common IoT ports
            result = subprocess.run(
                ['nmap', '-sV', '-p', '80,443,1883,8883,5683,5684,8080,8443', ip_address],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                services, open_ports = self._parse_service_scan(result.stdout)
        
        except Exception as e:
            logger.error(f"Service scan failed for {ip_address}: {e}")
        
        return {
            'services': services,
            'open_ports': open_ports,
            'protocols': self._infer_protocols(services, open_ports)
        }
    
    def _parse_nmap_output(self, nmap_output: str) -> List[Dict[str, Any]]:
        """Parse nmap output to extract device information"""
        devices = []
        
        host_pattern = r"Nmap scan report for (.+)"
        mac_pattern = r"MAC Address: ([0-9A-Fa-f:]+) \((.+)\)"
        ip_pattern = r"(\d+\.\d+\.\d+\.\d+)"
        
        current_host = None
        current_mac = None
        current_manufacturer = "Unknown"
        
        for line in nmap_output.split('\n'):
            host_match = re.match(host_pattern, line)
            if host_match:
                current_host = host_match.group(1)
            
            mac_match = re.match(mac_pattern, line)
            if mac_match:
                current_mac = mac_match.group(1)
                current_manufacturer = mac_match.group(2)
                
                ip_match = re.search(ip_pattern, current_host or "")
                current_ip = ip_match.group(1) if ip_match else "Unknown"
                
                if current_mac and current_ip != "Unknown":
                    device_info = {
                        "device_name": self._generate_device_name(current_manufacturer, current_mac),
                        "mac_address": current_mac,
                        "ip_address": current_ip,
                        "manufacturer": current_manufacturer,
                        "device_type": self._infer_device_type(current_manufacturer, current_mac),
                        "firmware_version": "Unknown",
                        "protocols": [],
                        "status": "Active",
                        "last_seen": datetime.now()
                    }
                    devices.append(device_info)
                    
                    current_host = None
                    current_mac = None
                    current_manufacturer = "Unknown"
        
        return devices
    
    def _parse_service_scan(self, nmap_output: str) -> tuple[List[str], List[int]]:
        """Parse service scan results"""
        services = []
        open_ports = []
        
        port_pattern = r"(\d+)/(\w+)\s+(\w+)\s+(.+)"
        
        for line in nmap_output.split('\n'):
            match = re.match(port_pattern, line.strip())
            if match:
                port = int(match.group(1))
                state = match.group(3)
                service_info = match.group(4)
                
                if state == 'open':
                    open_ports.append(port)
                    services.append(f"{port}: {service_info}")
        
        return services, open_ports
    
    def _enhance_device_discovery(self, device: IoTDevice) -> IoTDevice:
        """Enhance device information with additional probes"""
        
        # HTTP/HTTPS probing
        http_info = self._probe_http_service(device.ip_address)
        if http_info:
            device.services.extend(http_info.get('services', []))
            device.device_model = http_info.get('device_model')
            device.firmware_version = http_info.get('firmware_version', device.firmware_version)
        
        # MQTT probing
        if self._check_mqtt_service(device.ip_address):
            device.protocols.append(Protocol.MQTT)
        
        # Additional protocol checks
        if self._check_coap_service(device.ip_address):
            device.protocols.append(Protocol.COAP)
        
        return device
    
    def _probe_http_service(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Probe HTTP/HTTPS services for additional information"""
        try:
            for scheme in ['http', 'https']:
                for port in [80, 443, 8080, 8443]:
                    url = f"{scheme}://{ip_address}:{port}"
                    try:
                        response = requests.get(url, timeout=5, verify=False)
                        if response.status_code == 200:
                            return {
                                'services': [f'{scheme.upper()} Web Interface'],
                                'device_model': self._extract_from_headers(response.headers),
                                'firmware_version': self._extract_version_from_response(response.text)
                            }
                    except:
                        continue
        except Exception as e:
            logger.debug(f"HTTP probe failed for {ip_address}: {e}")
        
        return None
    
    def _check_mqtt_service(self, ip_address: str) -> bool:
        """Check if MQTT service is running"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip_address, 1883))
            sock.close()
            return result == 0
        except:
            return False
    
    def _check_coap_service(self, ip_address: str) -> bool:
        """Check if CoAP service is running"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip_address, 5683))
            sock.close()
            return result == 0
        except:
            return False
    
    def _extract_from_headers(self, headers: Dict) -> str:
        """Extract device information from HTTP headers"""
        server = headers.get('Server', '')
        if 'nest' in server.lower():
            return 'Nest Thermostat'
        elif 'arlo' in server.lower():
            return 'Arlo Camera'
        elif 'tp-link' in server.lower():
            return 'TP-Link Router'
        return ''
    
    def _extract_version_from_response(self, html_content: str) -> str:
        """Extract version information from HTML response"""
        version_patterns = [
            r'firmware[^>]*>([^<]+)',
            r'version[^>]*>([^<]+)',
            r'v(\d+\.\d+\.\d+)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return "Unknown"
    
    def _assess_device_risk(self, device: IoTDevice) -> IoTDevice:
        """Assess device risk based on various factors"""
        risk_score = 0
        
        # Risk factors
        if device.firmware_version == "Unknown":
            risk_score += 100
        
        if any(port in device.open_ports for port in [23, 21, 22]):  # Telnet, FTP, SSH
            risk_score += 150
        
        if Protocol.HTTP in device.protocols and Protocol.HTTPS not in device.protocols:
            risk_score += 100
        
        if any(keyword in device.device_name.lower() for keyword in ['camera', 'security', 'lock']):
            risk_score += 50
        
        # Default credentials risk
        if any(brand in device.manufacturer.lower() for brand in ['d-link', 'tp-link', 'netgear']):
            risk_score += 75
        
        device.risk_score = risk_score
        
        # Add sample CVEs for demonstration
        if risk_score > 400:
            device.cves = ["CVE-2023-1234", "CVE-2023-5678"]
        
        return device
    
    def _infer_device_type(self, manufacturer: str, mac_address: str) -> str:
        """Enhanced device type inference"""
        manufacturer_lower = manufacturer.lower()
        mac_prefix = mac_address[:8].upper()
        
        # MAC address based inference
        mac_manufacturers = {
            '00:1B:44': 'Cisco', '00:24:FE': 'Huawei', '00:26:5A': 'Netgear',
            '00:1D:0F': 'Samsung', '00:1E:E1': 'Sony', '00:23:D4': 'Apple',
            '00:1C:B3': 'Belkin', '00:22:3F': 'Roku', '00:1F:5B': 'Google'
        }
        
        if mac_prefix in mac_manufacturers:
            manufacturer = mac_manufacturers[mac_prefix]
            manufacturer_lower = manufacturer.lower()
        
        if any(keyword in manufacturer_lower for keyword in ['camera', 'd-link', 'axis', 'arlo', 'nest cam']):
            return DeviceType.CAMERA.value
        elif any(keyword in manufacturer_lower for keyword in ['thermostat', 'nest', 'ecobee', 'honeywell']):
            return DeviceType.THERMOSTAT.value
        elif any(keyword in manufacturer_lower for keyword in ['router', 'cisco', 'netgear', 'tp-link', 'linksys']):
            return DeviceType.ROUTER.value
        elif any(keyword in manufacturer_lower for keyword in ['lock', 'schlage', 'august', 'yale']):
            return DeviceType.LOCK.value
        elif any(keyword in manufacturer_lower for keyword in ['sensor', 'temperature', 'humidity', 'motion']):
            return DeviceType.SENSOR.value
        elif any(keyword in manufacturer_lower for keyword in ['light', 'philips hue', 'lifx']):
            return DeviceType.LIGHT.value
        elif any(keyword in manufacturer_lower for keyword in ['speaker', 'alexa', 'google home', 'sonos']):
            return DeviceType.SPEAKER.value
        elif any(keyword in manufacturer_lower for keyword in ['plug', 'switch', 'outlet']):
            return DeviceType.PLUG.value
        else:
            return DeviceType.OTHER.value
    
    def _infer_protocols(self, services: List[str], open_ports: List[int]) -> List[str]:
        """Infer protocols from services and open ports"""
        protocols = []
        
        for service in services:
            if 'mqtt' in service.lower():
                protocols.append(Protocol.MQTT.value)
            elif 'http' in service.lower():
                protocols.append(Protocol.HTTP.value)
            elif 'https' in service.lower():
                protocols.append(Protocol.HTTPS.value)
            elif 'coap' in service.lower():
                protocols.append(Protocol.COAP.value)
        
        # Port-based inference
        port_protocols = {
            1883: Protocol.MQTT.value,
            8883: Protocol.MQTT.value,
            5683: Protocol.COAP.value,
            5684: Protocol.COAP.value,
            80: Protocol.HTTP.value,
            443: Protocol.HTTPS.value
        }
        
        for port in open_ports:
            if port in port_protocols and port_protocols[port] not in protocols:
                protocols.append(port_protocols[port])
        
        return protocols
    
    def _generate_device_name(self, manufacturer: str, mac_address: str) -> str:
        """Generate meaningful device name"""
        base_name = manufacturer.split()[0] if manufacturer != "Unknown" else "IoT"
        mac_suffix = mac_address.replace(':', '')[-6:].upper()
        return f"{base_name}_Device_{mac_suffix}"
    
    def _create_iot_device(self, device_info: Dict[str, Any]) -> IoTDevice:
        """Create IoTDevice object from scan data"""
        protocols = [Protocol(p) for p in device_info.get('protocols', [])]
        
        return IoTDevice(
            device_name=device_info['device_name'],
            mac_address=device_info['mac_address'],
            ip_address=device_info['ip_address'],
            manufacturer=device_info['manufacturer'],
            device_type=DeviceType(device_info['device_type']),
            firmware_version=device_info.get('firmware_version', 'Unknown'),
            protocols=protocols,
            last_seen=device_info.get('last_seen', datetime.now()),
            status=DeviceStatus.ACTIVE,
            open_ports=device_info.get('open_ports', []),
            services=device_info.get('services', []),
            risk_score=device_info.get('risk_score', 0)
        )
    
    def get_scan_progress(self) -> Dict[str, Any]:
        """Get current scan progress"""
        return self.scan_progress
    
    def get_local_network_ranges(self) -> List[str]:
        """Get common local network ranges for dropdown"""
        return [
            "192.168.1.0/24",
            "192.168.0.0/24", 
            "10.0.0.0/24",
            "172.16.0.0/24",
            "192.168.2.0/24"
        ]


class PassiveFingerprinter:
    """Passive network fingerprinting using various techniques"""
    
    def scan(self) -> List[IoTDevice]:
        """Perform passive network fingerprinting"""
        devices = []
        # This would implement mDNS, SSDP, DHCP listening etc.
        # For now, return empty list - implementation would require root privileges
        return devices