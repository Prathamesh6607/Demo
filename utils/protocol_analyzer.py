import socket
import struct
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import re
import requests
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class ProtocolAnalyzer:
    def __init__(self):
        self.timeout = 5
        
    def analyze_mqtt(self, host: str, port: int = 1883) -> Dict[str, Any]:
        """Analyze MQTT broker and devices"""
        try:
            result = {
                'protocol': 'MQTT',
                'port': port,
                'accessible': False,
                'authentication_required': False,
                'topics': [],
                'clients': [],
                'vulnerabilities': []
            }
            
            # Try to connect to MQTT broker
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((host, port))
                result['accessible'] = True
                
                # Send MQTT CONNECT packet
                connect_packet = self._build_mqtt_connect()
                sock.send(connect_packet)
                
                # Read response
                response = sock.recv(1024)
                if response:
                    connack = self._parse_mqtt_connack(response)
                    result['authentication_required'] = connack.get('auth_required', False)
                
                # Try to discover topics (limited without credentials)
                result['vulnerabilities'] = self._check_mqtt_vulnerabilities(host, port)
                
            except Exception as e:
                logger.debug(f"MQTT analysis failed for {host}:{port}: {e}")
            finally:
                sock.close()
            
            return result
            
        except Exception as e:
            logger.error(f"MQTT analysis error for {host}:{port}: {e}")
            return {
                'protocol': 'MQTT',
                'port': port,
                'accessible': False,
                'error': str(e)
            }

    def _build_mqtt_connect(self) -> bytes:
        """Build MQTT CONNECT packet"""
        # Fixed header: CONNECT (0x10)
        fixed_header = bytes([0x10])
        
        # Variable header
        protocol_name = b"MQTT"
        protocol_level = bytes([0x04])  # MQTT 3.1.1
        connect_flags = bytes([0x02])   # Clean session
        keep_alive = bytes([0x00, 0x3C])  # 60 seconds
        
        variable_header = (
            struct.pack("!H", len(protocol_name)) + protocol_name +
            protocol_level + connect_flags + keep_alive
        )
        
        # No payload for anonymous connection attempt
        payload = b""
        
        # Remaining length
        remaining_length = len(variable_header) + len(payload)
        fixed_header += self._encode_mqtt_length(remaining_length)
        
        return fixed_header + variable_header + payload

    def _encode_mqtt_length(self, length: int) -> bytes:
        """Encode MQTT remaining length"""
        encoded = b""
        while True:
            digit = length % 128
            length //= 128
            if length > 0:
                digit |= 0x80
            encoded += bytes([digit])
            if length <= 0:
                break
        return encoded

    def _parse_mqtt_connack(self, data: bytes) -> Dict[str, Any]:
        """Parse MQTT CONNACK packet"""
        if len(data) < 4:
            return {}
        
        try:
            # CONNACK is 4 bytes: 0x20, 0x02, 0x00, 0x00
            # Byte 3: Connect Acknowledge Flags
            # Byte 4: Connect Return Code
            connack_flags = data[2]
            return_code = data[3]
            
            return {
                'session_present': bool(connack_flags & 0x01),
                'auth_required': return_code == 0x05,  # 0x05 = Not authorized
                'return_code': return_code
            }
        except:
            return {}

    def _check_mqtt_vulnerabilities(self, host: str, port: int) -> List[Dict[str, Any]]:
        """Check for common MQTT vulnerabilities"""
        vulnerabilities = []
        
        # Check for anonymous access
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Try anonymous connection
            connect_packet = self._build_mqtt_connect()
            sock.send(connect_packet)
            response = sock.recv(1024)
            
            if response and len(response) >= 4 and response[3] == 0x00:
                vulnerabilities.append({
                    'type': 'anonymous_access',
                    'severity': 'high',
                    'description': 'MQTT broker allows anonymous connections',
                    'recommendation': 'Enable authentication on MQTT broker'
                })
            
            sock.close()
        except:
            pass
        
        # Check for unencrypted communication
        if port == 1883:  # Standard unencrypted MQTT port
            vulnerabilities.append({
                'type': 'unencrypted_communication',
                'severity': 'medium',
                'description': 'MQTT communication is not encrypted',
                'recommendation': 'Use MQTT over TLS (port 8883)'
            })
        
        return vulnerabilities

    def analyze_upnp(self, host: str, port: int = 1900) -> Dict[str, Any]:
        """Analyze UPnP services"""
        try:
            result = {
                'protocol': 'UPnP',
                'port': port,
                'services': [],
                'vulnerabilities': []
            }
            
            # Send M-SEARCH discovery request
            search_request = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                "MAN: \"ssdp:discover\"\r\n"
                "MX: 3\r\n"
                "ST: ssdp:all\r\n"
                "\r\n"
            )
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(search_request.encode(), (host, port))
            
            responses = []
            start_time = datetime.now()
            
            while (datetime.now() - start_time).total_seconds() < self.timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    response = data.decode('utf-8', errors='ignore')
                    responses.append(response)
                    
                    # Parse UPnP response
                    service_info = self._parse_upnp_response(response)
                    if service_info:
                        result['services'].append(service_info)
                        
                except socket.timeout:
                    break
            
            sock.close()
            
            # Check for UPnP vulnerabilities
            result['vulnerabilities'] = self._check_upnp_vulnerabilities(responses)
            
            return result
            
        except Exception as e:
            logger.error(f"UPnP analysis error for {host}:{port}: {e}")
            return {
                'protocol': 'UPnP',
                'port': port,
                'error': str(e)
            }

    def _parse_upnp_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse UPnP discovery response"""
        lines = response.split('\r\n')
        service_info = {}
        
        for line in lines:
            if line.startswith('SERVER:'):
                service_info['server'] = line.split(':', 1)[1].strip()
            elif line.startswith('LOCATION:'):
                service_info['location'] = line.split(':', 1)[1].strip()
            elif line.startswith('ST:'):
                service_info['service_type'] = line.split(':', 1)[1].strip()
            elif line.startswith('USN:'):
                service_info['usn'] = line.split(':', 1)[1].strip()
        
        return service_info if service_info else None

    def _check_upnp_vulnerabilities(self, responses: List[str]) -> List[Dict[str, Any]]:
        """Check for UPnP vulnerabilities"""
        vulnerabilities = []
        
        if responses:
            vulnerabilities.append({
                'type': 'upnp_enabled',
                'severity': 'medium',
                'description': 'UPnP service is enabled and discoverable',
                'recommendation': 'Disable UPnP if not required'
            })
        
        # Check for specific UPnP implementation vulnerabilities
        for response in responses:
            if 'Internet Gateway Device' in response:
                vulnerabilities.append({
                    'type': 'igdp_exposed',
                    'severity': 'high',
                    'description': 'Internet Gateway Device Protocol exposed',
                    'recommendation': 'Restrict UPnP access to trusted networks'
                })
                break
        
        return vulnerabilities

    def analyze_coap(self, host: str, port: int = 5683) -> Dict[str, Any]:
        """Analyze CoAP services"""
        try:
            result = {
                'protocol': 'CoAP',
                'port': port,
                'resources': [],
                'vulnerabilities': []
            }
            
            # Try to discover CoAP resources
            resources = self._discover_coap_resources(host, port)
            result['resources'] = resources
            
            # Check for CoAP vulnerabilities
            result['vulnerabilities'] = self._check_coap_vulnerabilities(host, port, resources)
            
            return result
            
        except Exception as e:
            logger.error(f"CoAP analysis error for {host}:{port}: {e}")
            return {
                'protocol': 'CoAP',
                'port': port,
                'error': str(e)
            }

    def _discover_coap_resources(self, host: str, port: int) -> List[str]:
        """Discover CoAP resources using .well-known/core"""
        resources = []
        
        try:
            # Build CoAP GET request for .well-known/core
            coap_get = self._build_coap_get_request('.well-known/core')
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(coap_get, (host, port))
            
            response, _ = sock.recvfrom(1024)
            sock.close()
            
            # Parse CoAP response
            if response:
                resource_links = self._parse_coap_response(response)
                resources.extend(resource_links)
                
        except:
            pass
        
        return resources

    def _build_coap_get_request(self, path: str) -> bytes:
        """Build CoAP GET request"""
        # CoAP header (simplified)
        # Version(2), Type(0), Token Length(0), Code(1=GET), Message ID(1234)
        header = bytes([0x40, 0x01, 0x04, 0xD2])
        
        # Options: Uri-Path
        path_parts = path.split('/')
        options = b""
        
        for part in path_parts:
            if part:
                # Uri-Path option (11)
                options += bytes([0xB0 + len(part)])  # Delta=11, Length=len(part)
                options += part.encode()
        
        # Payload marker and empty payload
        payload_marker = bytes([0xFF])
        
        return header + options + payload_marker

    def _parse_coap_response(self, data: bytes) -> List[str]:
        """Parse CoAP response to extract resource links"""
        resources = []
        
        try:
            if len(data) < 4:
                return resources
            
            # Skip header and look for payload
            payload_start = 4
            while payload_start < len(data) and data[payload_start] != 0xFF:
                payload_start += 1
            
            if payload_start < len(data) - 1:
                payload = data[payload_start + 1:].decode('utf-8', errors='ignore')
                
                # Parse CoRE Link Format
                links = re.findall(r'<([^>]+)>', payload)
                resources.extend(links)
                
        except:
            pass
        
        return resources

    def _check_coap_vulnerabilities(self, host: str, port: int, resources: List[str]) -> List[Dict[str, Any]]:
        """Check for CoAP vulnerabilities"""
        vulnerabilities = []
        
        if resources:
            vulnerabilities.append({
                'type': 'coap_resources_exposed',
                'severity': 'medium',
                'description': f'CoAP resources discoverable: {len(resources)} resources found',
                'recommendation': 'Implement CoAP security with DTLS'
            })
        
        # Check for unencrypted CoAP
        if port == 5683:  # Standard unencrypted CoAP port
            vulnerabilities.append({
                'type': 'unencrypted_coap',
                'severity': 'medium',
                'description': 'CoAP communication is not encrypted',
                'recommendation': 'Use CoAP over DTLS (port 5684)'
            })
        
        return vulnerabilities

    def analyze_http_services(self, host: str, ports: List[int] = None) -> Dict[str, Any]:
        """Analyze HTTP/HTTPS services"""
        if ports is None:
            ports = [80, 443, 8080, 8443]
        
        result = {
            'protocol': 'HTTP/HTTPS',
            'services': []
        }
        
        for port in ports:
            service_info = self._analyze_http_service(host, port)
            if service_info:
                result['services'].append(service_info)
        
        return result

    def _analyze_http_service(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Analyze individual HTTP service"""
        try:
            scheme = 'https' if port in [443, 8443] else 'http'
            url = f"{scheme}://{host}:{port}"
            
            response = requests.get(
                url, 
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            service_info = {
                'port': port,
                'scheme': scheme,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'server': response.headers.get('Server', 'Unknown'),
                'title': self._extract_html_title(response.text),
                'vulnerabilities': self._check_http_vulnerabilities(response)
            }
            
            return service_info
            
        except Exception as e:
            logger.debug(f"HTTP analysis failed for {host}:{port}: {e}")
            return None

    def _extract_html_title(self, html: str) -> str:
        """Extract title from HTML content"""
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE)
        return title_match.group(1).strip() if title_match else 'No Title'

    def _check_http_vulnerabilities(self, response: requests.Response) -> List[Dict[str, Any]]:
        """Check for HTTP service vulnerabilities"""
        vulnerabilities = []
        
        # Check for information disclosure in headers
        server_header = response.headers.get('Server', '')
        if server_header and 'test' in server_header.lower():
            vulnerabilities.append({
                'type': 'server_info_disclosure',
                'severity': 'low',
                'description': f'Server header reveals implementation: {server_header}',
                'recommendation': 'Minimize information in server headers'
            })
        
        # Check for missing security headers
        security_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options', 
            'X-XSS-Protection',
            'Strict-Transport-Security'
        ]
        
        for header in security_headers:
            if header not in response.headers:
                vulnerabilities.append({
                    'type': 'missing_security_header',
                    'severity': 'low',
                    'description': f'Missing security header: {header}',
                    'recommendation': f'Implement {header} header'
                })
        
        # Check for default pages
        if response.status_code == 200:
            page_content = response.text.lower()
            default_indicators = [
                'welcome to nginx',
                'apache2 ubuntu default page',
                'iis windows',
                'test page for'
            ]
            
            for indicator in default_indicators:
                if indicator in page_content:
                    vulnerabilities.append({
                        'type': 'default_page_exposed',
                        'severity': 'medium',
                        'description': 'Default web server page exposed',
                        'recommendation': 'Replace default pages with custom content'
                    })
                    break
        
        return vulnerabilities

    def comprehensive_protocol_analysis(self, host: str) -> Dict[str, Any]:
        """Perform comprehensive protocol analysis on a host"""
        protocols_to_check = [
            ('MQTT', 1883),
            ('MQTTS', 8883),
            ('CoAP', 5683),
            ('CoAPS', 5684),
            ('UPnP', 1900),
            ('HTTP', 80),
            ('HTTPS', 443)
        ]
        
        results = {
            'host': host,
            'timestamp': datetime.now().isoformat(),
            'protocols': {}
        }
        
        for protocol_name, port in protocols_to_check:
            try:
                if protocol_name == 'MQTT':
                    analysis = self.analyze_mqtt(host, port)
                elif protocol_name == 'CoAP':
                    analysis = self.analyze_coap(host, port)
                elif protocol_name == 'UPnP':
                    analysis = self.analyze_upnp(host, port)
                elif protocol_name in ['HTTP', 'HTTPS']:
                    # HTTP analysis is handled separately
                    continue
                else:
                    analysis = {'protocol': protocol_name, 'port': port, 'accessible': False}
                
                results['protocols'][protocol_name] = analysis
                
            except Exception as e:
                logger.error(f"Protocol analysis failed for {protocol_name} on {host}:{port}: {e}")
                results['protocols'][protocol_name] = {
                    'protocol': protocol_name,
                    'port': port,
                    'error': str(e)
                }
        
        # Add HTTP services analysis
        http_analysis = self.analyze_http_services(host)
        results['protocols']['HTTP_SERVICES'] = http_analysis
        
        return results