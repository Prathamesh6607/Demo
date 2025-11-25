from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum
import json

class DeviceStatus(str, Enum):
    ACTIVE = "Active"
    INACTIVE = "Inactive"
    UNKNOWN = "Unknown"
    QUARANTINED = "Quarantined"
    AT_RISK = "At Risk"
    ANOMALOUS = "Anomalous"

class DeviceType(str, Enum):
    CAMERA = "Security Camera"
    THERMOSTAT = "Thermostat"
    ROUTER = "WiFi Router"
    LOCK = "Smart Lock"
    GATEWAY = "Gateway"
    SENSOR = "Sensor"
    ACTUATOR = "Actuator"
    LIGHT = "Smart Light"
    SPEAKER = "Smart Speaker"
    PLUG = "Smart Plug"
    APPLIANCE = "Smart Appliance"
    OTHER = "Other"

class Protocol(str, Enum):
    MQTT = "MQTT"
    COAP = "CoAP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    BLE = "BLE"
    ZIGBEE = "Zigbee"
    LWM2M = "LWM2M"
    MODBUS = "Modbus"
    BACNET = "BACnet"
    SSDP = "SSDP"
    MDNS = "mDNS"
    DNS_SD = "DNS-SD"

class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class IoTDevice:
    def __init__(
        self,
        device_name: str,
        mac_address: str,
        ip_address: str,
        manufacturer: str,
        device_type: DeviceType,
        firmware_version: str = "Unknown",
        protocols: Optional[List[Protocol]] = None,
        last_seen: Optional[datetime] = None,
        status: DeviceStatus = DeviceStatus.UNKNOWN,
        # New enhanced fields
        risk_score: int = 0,
        open_ports: Optional[List[int]] = None,
        services: Optional[List[str]] = None,
        cves: Optional[List[str]] = None,
        dhcp_fingerprint: Optional[str] = None,
        mdns_services: Optional[List[str]] = None,
        tls_cert_info: Optional[Dict[str, Any]] = None,
        communication_partners: Optional[List[str]] = None,
        data_usage: Optional[Dict[str, int]] = None,
        tags: Optional[List[str]] = None,
        device_model: Optional[str] = None,
        os_version: Optional[str] = None,
        first_seen: Optional[datetime] = None
    ):
        self.device_name = device_name
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.manufacturer = manufacturer
        self.device_type = device_type
        self.firmware_version = firmware_version
        self.protocols = protocols or []
        self.last_seen = last_seen or datetime.now()
        self.status = status
        self.first_seen = first_seen or datetime.now()
        
        # Enhanced identification fields
        self.risk_score = risk_score
        self.open_ports = open_ports or []
        self.services = services or []
        self.cves = cves or []
        self.dhcp_fingerprint = dhcp_fingerprint
        self.mdns_services = mdns_services or []
        self.tls_cert_info = tls_cert_info or {}
        self.communication_partners = communication_partners or []
        self.data_usage = data_usage or {"in": 0, "out": 0}
        self.tags = tags or []
        self.device_model = device_model
        self.os_version = os_version
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_name": self.device_name,
            "mac_address": self.mac_address,
            "ip_address": self.ip_address,
            "manufacturer": self.manufacturer,
            "device_type": self.device_type.value,
            "firmware_version": self.firmware_version,
            "protocols": [p.value for p in self.protocols],
            "last_seen": self.last_seen.isoformat(),
            "status": self.status.value,
            "first_seen": self.first_seen.isoformat(),
            # Enhanced fields
            "risk_score": self.risk_score,
            "risk_level": self.get_risk_level().value,
            "open_ports": self.open_ports,
            "services": self.services,
            "cves": self.cves,
            "cve_count": len(self.cves),
            "dhcp_fingerprint": self.dhcp_fingerprint,
            "mdns_services": self.mdns_services,
            "tls_cert_info": self.tls_cert_info,
            "communication_partners": self.communication_partners,
            "data_usage": self.data_usage,
            "tags": self.tags,
            "device_model": self.device_model,
            "os_version": self.os_version
        }
    
    def get_risk_level(self) -> RiskLevel:
        """Calculate risk level based on risk score"""
        if self.risk_score >= 800:
            return RiskLevel.CRITICAL
        elif self.risk_score >= 600:
            return RiskLevel.HIGH
        elif self.risk_score >= 400:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def update_last_seen(self):
        self.last_seen = datetime.now()
        self.status = DeviceStatus.ACTIVE
    
    def mark_inactive(self):
        self.status = DeviceStatus.INACTIVE
    
    def mark_quarantined(self):
        self.status = DeviceStatus.QUARANTINED
    
    def add_cve(self, cve_id: str):
        if cve_id not in self.cves:
            self.cves.append(cve_id)
    
    def add_tag(self, tag: str):
        if tag not in self.tags:
            self.tags.append(tag)
    
    def update_risk_score(self, score: int):
        self.risk_score = min(max(score, 0), 1000)  # Clamp between 0-1000
    
    def add_communication_partner(self, partner_ip: str):
        if partner_ip not in self.communication_partners:
            self.communication_partners.append(partner_ip)