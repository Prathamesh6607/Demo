import json
import pandas as pd
import numpy as np
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import sqlite3
from pathlib import Path
import re

logger = logging.getLogger(__name__)

class DataAnalyzer:
    def __init__(self, db_path: str = "iot_devices.db"):
        self.db_path = db_path
    
    def analyze_dataset(self, filepath: str) -> Dict[str, Any]:
        """Analyze uploaded dataset with enhanced analytics"""
        try:
            file_ext = Path(filepath).suffix.lower()
            
            if file_ext == '.csv':
                return self._analyze_csv_dataset(filepath)
            elif file_ext in ['.json', '.jsonl']:
                return self._analyze_json_dataset(filepath)
            else:
                return self._analyze_unknown_dataset(filepath)
                
        except Exception as e:
            logger.error(f"Dataset analysis failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'devices': [],
                'total_devices': 0,
                'file_type': 'unknown'
            }
    
    def _analyze_csv_dataset(self, filepath: str) -> Dict[str, Any]:
        """Analyze CSV dataset"""
        df = pd.read_csv(filepath)
        
        analysis = {
            'success': True,
            'file_type': 'csv',
            'total_devices': len(df),
            'columns': df.columns.tolist(),
            'data_types': df.dtypes.astype(str).to_dict(),
            'missing_values': df.isnull().sum().to_dict(),
            'basic_stats': self._get_basic_stats(df)
        }
        
        # Enhanced device analysis
        if 'device_type' in df.columns:
            analysis['device_type_distribution'] = df['device_type'].value_counts().to_dict()
        
        if 'manufacturer' in df.columns:
            analysis['manufacturer_distribution'] = df['manufacturer'].value_counts().to_dict()
        
        # Risk analysis if risk_score column exists
        if 'risk_score' in df.columns:
            analysis['risk_analysis'] = self._analyze_risk_scores(df['risk_score'])
        
        return analysis
    
    def _analyze_json_dataset(self, filepath: str) -> Dict[str, Any]:
        """Analyze JSON dataset"""
        with open(filepath, 'r') as f:
            if filepath.endswith('.jsonl'):
                data = [json.loads(line) for line in f]
            else:
                data = json.load(f)
        
        if not isinstance(data, list):
            data = [data]
        
        df = pd.DataFrame(data)
        
        analysis = {
            'success': True,
            'file_type': 'json',
            'total_devices': len(df),
            'columns': df.columns.tolist(),
            'data_types': df.dtypes.astype(str).to_dict(),
            'missing_values': df.isnull().sum().to_dict()
        }
        
        return analysis
    
    def _analyze_unknown_dataset(self, filepath: str) -> Dict[str, Any]:
        """Analyze unknown file format"""
        return {
            'success': False,
            'file_type': 'unknown',
            'error': 'Unsupported file format',
            'devices': [],
            'total_devices': 0
        }
    
    def _get_basic_stats(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Get basic statistics for numerical columns"""
        stats = {}
        numerical_cols = df.select_dtypes(include=[np.number]).columns
        
        for col in numerical_cols:
            stats[col] = {
                'mean': float(df[col].mean()),
                'median': float(df[col].median()),
                'std': float(df[col].std()),
                'min': float(df[col].min()),
                'max': float(df[col].max())
            }
        
        return stats
    
    def _analyze_risk_scores(self, risk_scores: pd.Series) -> Dict[str, Any]:
        """Analyze risk score distribution"""
        return {
            'distribution': {
                'critical': int((risk_scores >= 800).sum()),
                'high': int(((risk_scores >= 600) & (risk_scores < 800)).sum()),
                'medium': int(((risk_scores >= 400) & (risk_scores < 600)).sum()),
                'low': int((risk_scores < 400).sum())
            },
            'average_risk': float(risk_scores.mean()),
            'max_risk': float(risk_scores.max()),
            'min_risk': float(risk_scores.min())
        }
    
    def analyze_network_traffic(self, traffic_data: List[Dict]) -> Dict[str, Any]:
        """Analyze network traffic patterns"""
        if not traffic_data:
            return {'total_connections': 0, 'suspicious_activity': []}
        
        df = pd.DataFrame(traffic_data)
        
        # Analyze connection patterns
        source_ips = df['source_ip'].value_counts()
        dest_ips = df['destination_ip'].value_counts()
        
        suspicious_activity = []
        
        # Detect port scanning
        unique_ports_per_source = df.groupby('source_ip')['port'].nunique()
        port_scanners = unique_ports_per_source[unique_ports_per_source > 10]
        
        for ip in port_scanners.index:
            suspicious_activity.append({
                'type': 'port_scanning',
                'source_ip': ip,
                'ports_scanned': int(port_scanners[ip]),
                'severity': 'high'
            })
        
        # Detect data exfiltration
        large_transfers = df[df['bytes_sent'] > 1000000]  # 1MB threshold
        for _, transfer in large_transfers.iterrows():
            suspicious_activity.append({
                'type': 'large_data_transfer',
                'source_ip': transfer['source_ip'],
                'destination_ip': transfer['destination_ip'],
                'bytes_sent': int(transfer['bytes_sent']),
                'severity': 'medium'
            })
        
        return {
            'total_connections': len(df),
            'unique_sources': len(source_ips),
            'unique_destinations': len(dest_ips),
            'suspicious_activity': suspicious_activity,
            'top_sources': source_ips.head(10).to_dict(),
            'top_destinations': dest_ips.head(10).to_dict()
        }
    
    def detect_anomalies(self, devices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect anomalies in device behavior"""
        anomalies = []
        
        for device in devices:
            device_anomalies = self._analyze_device_anomalies(device)
            if device_anomalies:
                anomalies.extend(device_anomalies)
        
        return {
            'total_anomalies': len(anomalies),
            'anomalies': anomalies,
            'critical_count': len([a for a in anomalies if a['severity'] == 'critical']),
            'high_count': len([a for a in anomalies if a['severity'] == 'high'])
        }
    
    def _analyze_device_anomalies(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze individual device for anomalies"""
        anomalies = []
        
        # Check for default credentials risk
        if self._has_default_credentials(device):
            anomalies.append({
                'device': device.get('device_name', 'Unknown'),
                'type': 'default_credentials',
                'description': 'Device may be using default credentials',
                'severity': 'high'
            })
        
        # Check for outdated firmware
        if self._is_firmware_outdated(device):
            anomalies.append({
                'device': device.get('device_name', 'Unknown'),
                'type': 'outdated_firmware',
                'description': 'Device firmware may be outdated',
                'severity': 'medium'
            })
        
        # Check for unnecessary open ports
        open_ports = device.get('open_ports', [])
        risky_ports = [21, 23, 135, 139, 445]  # FTP, Telnet, NetBIOS
        found_risky_ports = [port for port in open_ports if port in risky_ports]
        
        if found_risky_ports:
            anomalies.append({
                'device': device.get('device_name', 'Unknown'),
                'type': 'risky_ports_open',
                'description': f'Device has risky ports open: {found_risky_ports}',
                'severity': 'medium'
            })
        
        return anomalies
    
    def _has_default_credentials(self, device: Dict[str, Any]) -> bool:
        """Check if device is known for default credentials"""
        manufacturer = device.get('manufacturer', '').lower()
        risky_brands = ['d-link', 'tp-link', 'netgear', 'linksys', 'tenda']
        return any(brand in manufacturer for brand in risky_brands)
    
    def _is_firmware_outdated(self, device: Dict[str, Any]) -> bool:
        """Check if firmware appears outdated"""
        firmware = device.get('firmware_version', '').lower()
        
        # Simple heuristic - if firmware version is very old format
        old_patterns = [r'v?\d+\.\d+', r'v?\d+\.\d+\.\d+']
        for pattern in old_patterns:
            if re.search(pattern, firmware):
                return True
        
        return False
    
    def generate_security_recommendations(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        anomalies = analysis_results.get('anomalies', [])
        risk_analysis = analysis_results.get('risk_analysis', {})
        
        # Recommendations based on anomalies
        if any(a['severity'] in ['high', 'critical'] for a in anomalies):
            recommendations.extend([
                "Immediately change default credentials on affected devices",
                "Isolate high-risk devices from critical network segments",
                "Implement network segmentation for IoT devices"
            ])
        
        # Recommendations based on risk scores
        if risk_analysis.get('critical_count', 0) > 0:
            recommendations.append("Prioritize patching devices with critical risk scores")
        
        # General IoT security recommendations
        general_recommendations = [
            "Implement regular firmware update procedures",
            "Use network segmentation for IoT devices",
            "Monitor IoT device network traffic",
            "Disable unnecessary services and ports",
            "Use strong, unique passwords for all devices"
        ]
        
        recommendations.extend(general_recommendations)
        return list(set(recommendations))  # Remove duplicates
    
    def generate_nist_compliance_report(self, devices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate NIST Cybersecurity Framework compliance report"""
        
        # Analyze compliance with NIST CSF categories
        identify_score = self._assess_identify_category(devices)
        protect_score = self._assess_protect_category(devices)
        detect_score = self._assess_detect_category(devices)
        respond_score = self._assess_respond_category(devices)
        recover_score = self._assess_recover_category(devices)
        
        overall_score = (identify_score + protect_score + detect_score + respond_score + recover_score) / 5
        
        return {
            'nist_compliance_score': round(overall_score, 1),
            'categories': {
                'identify': {
                    'score': identify_score,
                    'status': 'compliant' if identify_score >= 80 else 'partial' if identify_score >= 60 else 'needs_improvement',
                    'recommendations': self._get_identify_recommendations(identify_score)
                },
                'protect': {
                    'score': protect_score,
                    'status': 'compliant' if protect_score >= 80 else 'partial' if protect_score >= 60 else 'needs_improvement',
                    'recommendations': self._get_protect_recommendations(protect_score)
                },
                'detect': {
                    'score': detect_score,
                    'status': 'compliant' if detect_score >= 80 else 'partial' if detect_score >= 60 else 'needs_improvement',
                    'recommendations': self._get_detect_recommendations(detect_score)
                },
                'respond': {
                    'score': respond_score,
                    'status': 'compliant' if respond_score >= 80 else 'partial' if respond_score >= 60 else 'needs_improvement',
                    'recommendations': self._get_respond_recommendations(respond_score)
                },
                'recover': {
                    'score': recover_score,
                    'status': 'compliant' if recover_score >= 80 else 'partial' if recover_score >= 60 else 'needs_improvement',
                    'recommendations': self._get_recover_recommendations(recover_score)
                }
            }
        }
    
    def _assess_identify_category(self, devices: List[Dict]) -> int:
        """Assess NIST Identify category compliance"""
        scores = []
        
        # Device inventory completeness
        total_devices = len(devices)
        if total_devices > 0:
            complete_devices = len([d for d in devices if d.get('manufacturer') and d.get('device_type')])
            scores.append((complete_devices / total_devices) * 100)
        
        # Risk assessment
        devices_with_risk = len([d for d in devices if d.get('risk_score', 0) > 0])
        if total_devices > 0:
            scores.append((devices_with_risk / total_devices) * 100)
        
        return int(np.mean(scores)) if scores else 0
    
    def _assess_protect_category(self, devices: List[Dict]) -> int:
        """Assess NIST Protect category compliance"""
        scores = []
        
        # Access control
        devices_with_auth = len([d for d in devices if d.get('protocols') and 'HTTPS' in d.get('protocols', [])])
        if len(devices) > 0:
            scores.append((devices_with_auth / len(devices)) * 100)
        
        # Data protection
        encrypted_devices = len([d for d in devices if any(p in d.get('protocols', []) for p in ['HTTPS', 'MQTTS'])])
        if len(devices) > 0:
            scores.append((encrypted_devices / len(devices)) * 50)  # Weighted
        
        return int(np.mean(scores)) if scores else 0
    
    def _assess_detect_category(self, devices: List[Dict]) -> int:
        """Assess NIST Detect category compliance"""
        # Simplified - in real implementation, this would check monitoring capabilities
        return 65
    
    def _assess_respond_category(self, devices: List[Dict]) -> int:
        """Assess NIST Respond category compliance"""
        # Simplified - in real implementation, this would check incident response capabilities
        return 55
    
    def _assess_recover_category(self, devices: List[Dict]) -> int:
        """Assess NIST Recover category compliance"""
        # Simplified - in real implementation, this would check recovery capabilities
        return 60
    
    def _get_identify_recommendations(self, score: int) -> List[str]:
        if score >= 80:
            return ["Maintain current asset management practices"]
        elif score >= 60:
            return ["Improve device inventory completeness", "Implement regular risk assessments"]
        else:
            return ["Establish comprehensive asset inventory", "Implement automated risk assessment", "Create device categorization system"]
    
    def _get_protect_recommendations(self, score: int) -> List[str]:
        if score >= 80:
            return ["Continue current protection measures"]
        elif score >= 60:
            return ["Enhance access control measures", "Implement network segmentation"]
        else:
            return ["Implement strong access controls", "Enable encryption for all communications", "Establish network segmentation"]
    
    def _get_detect_recommendations(self, score: int) -> List[str]:
        return ["Implement continuous monitoring", "Set up anomaly detection", "Establish security alerting"]
    
    def _get_respond_recommendations(self, score: int) -> List[str]:
        return ["Develop incident response plan", "Establish communication procedures", "Conduct regular drills"]
    
    def _get_recover_recommendations(self, score: int) -> List[str]:
        return ["Create recovery plans", "Establish backup procedures", "Test recovery capabilities"]