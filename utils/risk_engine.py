import logging
import math
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    LOW = "Low"
    MEDIUM = "Medium" 
    HIGH = "High"
    CRITICAL = "Critical"

@dataclass
class RiskFactor:
    name: str
    weight: float
    value: float
    description: str

class RiskEngine:
    def __init__(self):
        self.risk_weights = {
            'vulnerability_severity': 0.25,
            'device_criticality': 0.20,
            'network_exposure': 0.15,
            'authentication_strength': 0.15,
            'encryption_status': 0.10,
            'firmware_status': 0.10,
            'behavior_anomalies': 0.05
        }
        
        # Device criticality mapping
        self.device_criticality = {
            'router': 1.0,
            'gateway': 1.0,
            'camera': 0.8,
            'lock': 0.9,
            'thermostat': 0.6,
            'sensor': 0.5,
            'light': 0.3,
            'speaker': 0.4,
            'plug': 0.4,
            'other': 0.5
        }
        
        # Manufacturer risk factors
        self.manufacturer_risk = {
            'unknown': 0.8,
            'd-link': 0.7,
            'tp-link': 0.6,
            'netgear': 0.6,
            'linksys': 0.5,
            'cisco': 0.3,
            'apple': 0.4,
            'google': 0.4,
            'nest': 0.5
        }

    def calculate_device_risk(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate comprehensive risk score for a device
        Returns score from 0-1000 and risk level
        """
        try:
            risk_factors = []
            
            # 1. Vulnerability-based risk
            vuln_risk = self._calculate_vulnerability_risk(device)
            risk_factors.append(RiskFactor(
                name='vulnerability_severity',
                weight=self.risk_weights['vulnerability_severity'],
                value=vuln_risk,
                description=f'Vulnerability risk based on {len(device.get("cves", []))} CVEs'
            ))
            
            # 2. Device criticality
            criticality_risk = self._calculate_criticality_risk(device)
            risk_factors.append(RiskFactor(
                name='device_criticality',
                weight=self.risk_weights['device_criticality'],
                value=criticality_risk,
                description=f'Device criticality: {device.get("device_type", "unknown")}'
            ))
            
            # 3. Network exposure
            exposure_risk = self._calculate_exposure_risk(device)
            risk_factors.append(RiskFactor(
                name='network_exposure',
                weight=self.risk_weights['network_exposure'],
                value=exposure_risk,
                description=f'Network exposure based on {len(device.get("open_ports", []))} open ports'
            ))
            
            # 4. Authentication strength
            auth_risk = self._calculate_authentication_risk(device)
            risk_factors.append(RiskFactor(
                name='authentication_strength',
                weight=self.risk_weights['authentication_strength'],
                value=auth_risk,
                description='Authentication mechanism risk assessment'
            ))
            
            # 5. Encryption status
            encryption_risk = self._calculate_encryption_risk(device)
            risk_factors.append(RiskFactor(
                name='encryption_status',
                weight=self.risk_weights['encryption_status'],
                value=encryption_risk,
                description='Communication encryption assessment'
            ))
            
            # 6. Firmware status
            firmware_risk = self._calculate_firmware_risk(device)
            risk_factors.append(RiskFactor(
                name='firmware_status',
                weight=self.risk_weights['firmware_status'],
                value=firmware_risk,
                description='Firmware version and update status'
            ))
            
            # 7. Behavioral anomalies
            behavior_risk = self._calculate_behavior_risk(device)
            risk_factors.append(RiskFactor(
                name='behavior_anomalies',
                weight=self.risk_weights['behavior_anomalies'],
                value=behavior_risk,
                description='Behavioral anomaly detection'
            ))
            
            # Calculate weighted risk score (0-1000)
            total_risk = 0
            for factor in risk_factors:
                total_risk += factor.value * factor.weight * 10  # Scale to 0-1000
            
            total_risk = min(total_risk, 1000)  # Cap at 1000
            
            # Determine risk level
            risk_level = self._get_risk_level(total_risk)
            
            return {
                'risk_score': int(total_risk),
                'risk_level': risk_level.value,
                'risk_factors': [factor.__dict__ for factor in risk_factors],
                'calculation_timestamp': datetime.now().isoformat(),
                'recommendations': self._generate_risk_recommendations(risk_factors, risk_level)
            }
            
        except Exception as e:
            logger.error(f"Risk calculation failed for device {device.get('mac_address')}: {e}")
            return {
                'risk_score': 0,
                'risk_level': RiskLevel.LOW.value,
                'risk_factors': [],
                'error': str(e)
            }

    def _calculate_vulnerability_risk(self, device: Dict[str, Any]) -> float:
        """Calculate risk based on vulnerabilities"""
        cves = device.get('cves', [])
        if not cves:
            return 0.0
        
        # Calculate weighted vulnerability score
        total_vuln_score = 0
        for cve in cves:
            cvss_score = cve.get('cvss_score', 0.0)
            severity = cve.get('severity', 'LOW')
            
            # Use CVSS score if available, otherwise estimate from severity
            if cvss_score > 0:
                score = cvss_score / 10.0  # Normalize to 0-1
            else:
                severity_weights = {
                    'CRITICAL': 1.0,
                    'HIGH': 0.8,
                    'MEDIUM': 0.5,
                    'LOW': 0.2
                }
                score = severity_weights.get(severity.upper(), 0.1)
            
            total_vuln_score += score
        
        # Average and scale
        avg_score = total_vuln_score / len(cves)
        return min(avg_score * 1.5, 1.0)  # Cap at 1.0

    def _calculate_criticality_risk(self, device: Dict[str, Any]) -> float:
        """Calculate risk based on device criticality"""
        device_type = device.get('device_type', 'other').lower()
        manufacturer = device.get('manufacturer', 'unknown').lower()
        
        # Base criticality from device type
        base_criticality = self.device_criticality.get(device_type, 0.5)
        
        # Adjust based on manufacturer reputation
        manufacturer_factor = self.manufacturer_risk.get(manufacturer, 0.5)
        
        # Combine factors
        criticality = (base_criticality + manufacturer_factor) / 2
        
        return min(criticality, 1.0)

    def _calculate_exposure_risk(self, device: Dict[str, Any]) -> float:
        """Calculate risk based on network exposure"""
        open_ports = device.get('open_ports', [])
        protocols = device.get('protocols', [])
        
        if not open_ports:
            return 0.1  # Minimal risk if no open ports
        
        # Risk factors for different port types
        high_risk_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
        medium_risk_ports = [161, 162, 389, 636, 1433, 1521, 2375, 2376, 3000, 5000, 5432, 6379, 7474, 7687, 8000, 8008, 8081, 8443, 8888, 9000, 9200, 9300, 11211, 27017]
        
        risk_score = 0.0
        
        # Check for high-risk ports
        high_risk_count = len([port for port in open_ports if port in high_risk_ports])
        risk_score += high_risk_count * 0.2
        
        # Check for medium-risk ports  
        medium_risk_count = len([port for port in open_ports if port in medium_risk_ports])
        risk_score += medium_risk_count * 0.1
        
        # Check for unencrypted protocols
        if 'HTTP' in protocols and 'HTTPS' not in protocols:
            risk_score += 0.3
        
        if 'MQTT' in protocols and 'MQTTS' not in protocols:
            risk_score += 0.2
        
        if 'FTP' in protocols:
            risk_score += 0.4
        
        if 'TELNET' in protocols:
            risk_score += 0.5
        
        return min(risk_score, 1.0)

    def _calculate_authentication_risk(self, device: Dict[str, Any]) -> float:
        """Calculate risk based on authentication mechanisms"""
        protocols = device.get('protocols', [])
        services = device.get('services', [])
        
        risk_score = 0.0
        
        # Check for protocols with weak authentication
        if 'TELNET' in protocols:
            risk_score += 0.8  # Telnet has no encryption
        
        if 'FTP' in protocols:
            risk_score += 0.6  # FTP sends credentials in clear text
        
        if 'HTTP' in protocols and 'HTTPS' not in protocols:
            risk_score += 0.4  # Basic auth over HTTP
        
        # Check for default credential risks
        manufacturer = device.get('manufacturer', '').lower()
        if any(brand in manufacturer for brand in ['d-link', 'tp-link', 'netgear', 'linksys']):
            risk_score += 0.5
        
        # Check if device has known default credentials
        if device.get('has_default_credentials', False):
            risk_score += 0.7
        
        return min(risk_score, 1.0)

    def _calculate_encryption_risk(self, device: Dict[str, Any]) -> float:
        """Calculate risk based on encryption status"""
        protocols = device.get('protocols', [])
        
        risk_score = 0.0
        encrypted_count = 0
        total_protocols = len(protocols)
        
        if total_protocols == 0:
            return 0.5  # Unknown risk
        
        # Count encrypted protocols
        encrypted_protocols = ['HTTPS', 'MQTTS', 'FTPS', 'SSH', 'TLS']
        for protocol in protocols:
            if any(encrypted in protocol.upper() for encrypted in encrypted_protocols):
                encrypted_count += 1
        
        # Calculate encryption ratio
        encryption_ratio = encrypted_count / total_protocols
        risk_score = 1.0 - encryption_ratio  # Higher risk for less encryption
        
        # Additional risk for specific unencrypted protocols
        if 'HTTP' in protocols and 'HTTPS' not in protocols:
            risk_score = max(risk_score, 0.8)
        
        if 'MQTT' in protocols and 'MQTTS' not in protocols:
            risk_score = max(risk_score, 0.6)
        
        return min(risk_score, 1.0)

    def _calculate_firmware_risk(self, device: Dict[str, Any]) -> float:
        """Calculate risk based on firmware status"""
        firmware = device.get('firmware_version', 'Unknown')
        manufacturer = device.get('manufacturer', '')
        
        if firmware == 'Unknown':
            return 0.8  # High risk for unknown firmware
        
        # Check for outdated firmware patterns
        risk_indicators = [
            r'v?1\.0',
            r'v?2\.0', 
            r'v?\d+\.\d+$',  # No patch version
            r'beta',
            r'test',
            r'debug'
        ]
        
        for pattern in risk_indicators:
            if re.search(pattern, firmware, re.IGNORECASE):
                return 0.7
        
        # Check for very old version numbers
        version_match = re.search(r'v?(\d+)\.(\d+)\.?(\d+)?', firmware)
        if version_match:
            major = int(version_match.group(1))
            minor = int(version_match.group(2))
            
            if major <= 1 and minor <= 5:
                return 0.6
        
        return 0.3  # Assume moderate risk for known firmware

    def _calculate_behavior_risk(self, device: Dict[str, Any]) -> float:
        """Calculate risk based on behavioral anomalies"""
        anomalies = device.get('anomalies', [])
        communication_partners = device.get('communication_partners', [])
        
        risk_score = 0.0
        
        # Anomaly-based risk
        if anomalies:
            high_severity_anomalies = len([a for a in anomalies if a.get('severity') in ['high', 'critical']])
            risk_score += high_severity_anomalies * 0.3
        
        # Communication pattern risk
        if len(communication_partners) > 50:  # Unusually high number of connections
            risk_score += 0.4
        
        # Check for external communications
        external_ips = [ip for ip in communication_partners if not self._is_private_ip(ip)]
        if external_ips and device.get('device_type') in ['sensor', 'camera']:
            risk_score += 0.3
        
        return min(risk_score, 1.0)

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is in private range"""
        try:
            ip_parts = [int(part) for part in ip.split('.')]
            
            # Check for private IP ranges
            if ip_parts[0] == 10:
                return True
            elif ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31:
                return True
            elif ip_parts[0] == 192 and ip_parts[1] == 168:
                return True
            elif ip_parts[0] == 169 and ip_parts[1] == 254:
                return True
            
            return False
        except:
            return False

    def _get_risk_level(self, risk_score: float) -> RiskLevel:
        """Convert risk score to risk level"""
        if risk_score >= 800:
            return RiskLevel.CRITICAL
        elif risk_score >= 600:
            return RiskLevel.HIGH
        elif risk_score >= 400:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def _generate_risk_recommendations(self, risk_factors: List[RiskFactor], risk_level: RiskLevel) -> List[str]:
        """Generate risk mitigation recommendations"""
        recommendations = []
        
        # Sort risk factors by impact (value * weight)
        sorted_factors = sorted(risk_factors, key=lambda x: x.value * x.weight, reverse=True)
        
        # Generate recommendations for top risk factors
        for factor in sorted_factors[:3]:  # Top 3 factors
            if factor.value > 0.5:  # Only address significant risks
                rec = self._get_factor_recommendation(factor)
                if rec:
                    recommendations.append(rec)
        
        # General recommendations based on risk level
        if risk_level == RiskLevel.CRITICAL:
            recommendations.extend([
                "Immediately isolate device from network",
                "Perform comprehensive security assessment",
                "Contact device manufacturer for security patches"
            ])
        elif risk_level == RiskLevel.HIGH:
            recommendations.extend([
                "Schedule immediate security updates",
                "Implement network segmentation",
                "Monitor device for suspicious activity"
            ])
        elif risk_level == RiskLevel.MEDIUM:
            recommendations.extend([
                "Apply security patches during next maintenance window",
                "Review and strengthen access controls",
                "Consider network segmentation"
            ])
        
        return list(set(recommendations))  # Remove duplicates

    def _get_factor_recommendation(self, factor: RiskFactor) -> Optional[str]:
        """Get specific recommendation for a risk factor"""
        recommendations = {
            'vulnerability_severity': 'Apply security patches and updates for identified vulnerabilities',
            'device_criticality': 'Implement additional monitoring and access controls for critical devices',
            'network_exposure': 'Close unnecessary ports and restrict network access',
            'authentication_strength': 'Strengthen authentication mechanisms and change default credentials',
            'encryption_status': 'Enable encryption for all network communications',
            'firmware_status': 'Update device firmware to latest secure version',
            'behavior_anomalies': 'Investigate and address detected behavioral anomalies'
        }
        
        return recommendations.get(factor.name)

    def calculate_network_risk(self, devices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall network risk assessment"""
        if not devices:
            return {
                'network_risk_score': 0,
                'network_risk_level': RiskLevel.LOW.value,
                'critical_devices': 0,
                'high_risk_devices': 0
            }
        
        total_risk = 0
        critical_count = 0
        high_risk_count = 0
        
        for device in devices:
            risk_score = device.get('risk_score', 0)
            total_risk += risk_score
            
            if risk_score >= 800:
                critical_count += 1
            elif risk_score >= 600:
                high_risk_count += 1
        
        avg_risk = total_risk / len(devices)
        network_risk_level = self._get_risk_level(avg_risk)
        
        return {
            'network_risk_score': int(avg_risk),
            'network_risk_level': network_risk_level.value,
            'critical_devices': critical_count,
            'high_risk_devices': high_risk_count,
            'total_devices': len(devices),
            'risk_distribution': {
                'critical': critical_count,
                'high': high_risk_count,
                'medium': len([d for d in devices if 400 <= d.get('risk_score', 0) < 600]),
                'low': len([d for d in devices if d.get('risk_score', 0) < 400])
            }
        }