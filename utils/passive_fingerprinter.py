import socket
import struct
import threading
import time
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass
import re

logger = logging.getLogger(__name__)

@dataclass
class PassiveDevice:
    mac_address: str
    ip_address: str
    hostname: str
    device_type: str
    manufacturer: str
    services: List[str]
    protocol: str
    timestamp: datetime

class PassiveFingerprinter:
    def __init__(self):
        self.discovered_devices = []
        self.is_listening = False
        self.listen_thread = None
        
        # DHCP fingerprint database
        self.dhcp_fingerprints = {
            '1,3,6,15,31,33,43,44,46,47,119,121,249,252': 'Windows',
            '1,3,6,15,31,33,43,44,46,47,119,121,249,252,42': 'Windows Server',
            '1,3,6,15,31,33,43,44,46,47,119,121,249,252,95': 'Linux',
            '1,3,6,15,31,33,43,44,46,47,119,121,249,252,108': 'Android',
            '1,3,6,15,31,33,43,44,46,47,119,121,249,252,116': 'iOS',
            '1,3,6,15,31,33,43,44,46,47,119,121,249': 'macOS',
            '1,3,6,15,31,33,43,44,46,47,119': 'IoT Device',
            '1,3,6,15,31,33': 'Basic IoT'
        }
        
        # mDNS service types for IoT devices
        self.iot_services = {
            '_hap._tcp.local.': 'HomeKit Accessory',
            '_googlecast._tcp.local.': 'Google Cast',
            '_airplay._tcp.local.': 'AirPlay',
            '_raop._tcp.local.': 'AirPlay Audio',
            '_sonos._tcp.local.': 'Sonos',
            '_printer._tcp.local.': 'Network Printer',
            '_ipps._tcp.local.': 'IPPS Printer',
            '_scanner._tcp.local.': 'Network Scanner',
            '_http._tcp.local.': 'Web Service',
            '_https._tcp.local.': 'HTTPS Service',
            '_ssh._tcp.local.': 'SSH Service',
            '_telnet._tcp.local.': 'Telnet Service',
            '_ftp._tcp.local.': 'FTP Service',
            '_mqtt._tcp.local.': 'MQTT Broker',
            '_coap._tcp.local.': 'CoAP Service',
            '_webrtc._tcp.local.': 'WebRTC Service',
            '_iot._tcp.local.': 'IoT Device'
        }

    def start_passive_scan(self, duration: int = 300) -> List[Dict[str, Any]]:
        """
        Start passive network scanning for specified duration
        """
        self.discovered_devices = []
        self.is_listening = True
        
        # Start listening threads for different protocols
        threads = [
            threading.Thread(target=self._listen_mdns, daemon=True),
            threading.Thread(target=self._listen_ssdp, daemon=True),
            threading.Thread(target=self._listen_dhcp, daemon=True),
            threading.Thread(target=self._listen_netbios, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
        
        logger.info(f"Started passive scanning for {duration} seconds")
        
        # Run for specified duration
        time.sleep(duration)
        self.is_listening = False
        
        # Wait for threads to finish
        for thread in threads:
            thread.join(timeout=5)
        
        return [device.__dict__ for device in self.discovered_devices]

    def _listen_mdns(self):
        """Listen for mDNS (Multicast DNS) announcements"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('', 5353))
            
            # Join multicast group
            mreq = struct.pack("4sl", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            while self.is_listening:
                try:
                    data, addr = sock.recvfrom(1024)
                    self._parse_mdns_packet(data, addr[0])
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.debug(f"mDNS listening error: {e}")
                    
            sock.close()
        except Exception as e:
            logger.error(f"mDNS listener failed: {e}")

    def _parse_mdns_packet(self, data: bytes, source_ip: str):
        """Parse mDNS packet to extract device information"""
        try:
            # Simple mDNS parsing - in practice, use dnslib for proper parsing
            data_str = data.decode('latin-1')
            
            # Look for service announcements
            for service, device_type in self.iot_services.items():
                if service.encode() in data:
                    # Extract hostname from mDNS packet
                    hostname_match = re.search(r'(\w+-\w+|\w+_\w+)', data_str)
                    hostname = hostname_match.group(1) if hostname_match else f"mDNS-{source_ip}"
                    
                    device = PassiveDevice(
                        mac_address="Unknown",  # mDNS doesn't provide MAC
                        ip_address=source_ip,
                        hostname=hostname,
                        device_type=device_type,
                        manufacturer=self._infer_manufacturer(service),
                        services=[service],
                        protocol="mDNS",
                        timestamp=datetime.now()
                    )
                    
                    self._add_device(device)
                    break
                    
        except Exception as e:
            logger.debug(f"mDNS parsing error: {e}")

    def _listen_ssdp(self):
        """Listen for SSDP (Simple Service Discovery Protocol) announcements"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('', 1900))
            
            # Join multicast group
            mreq = struct.pack("4sl", socket.inet_aton("239.255.255.250"), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            sock.settimeout(1)
            
            while self.is_listening:
                try:
                    data, addr = sock.recvfrom(1024)
                    self._parse_ssdp_packet(data.decode('utf-8', errors='ignore'), addr[0])
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.debug(f"SSDP listening error: {e}")
                    
            sock.close()
        except Exception as e:
            logger.error(f"SSDP listener failed: {e}")

    def _parse_ssdp_packet(self, data: str, source_ip: str):
        """Parse SSDP packet to extract device information"""
        try:
            lines = data.split('\r\n')
            device_info = {}
            
            for line in lines:
                if line.startswith('SERVER:'):
                    device_info['server'] = line.split(':', 1)[1].strip()
                elif line.startswith('LOCATION:'):
                    device_info['location'] = line.split(':', 1)[1].strip()
                elif line.startswith('USN:'):
                    device_info['usn'] = line.split(':', 1)[1].strip()
                elif line.startswith('NT:'):
                    device_info['nt'] = line.split(':', 1)[1].strip()
            
            if 'server' in device_info:
                manufacturer, device_type = self._parse_ssdp_server(device_info['server'])
                
                device = PassiveDevice(
                    mac_address="Unknown",
                    ip_address=source_ip,
                    hostname=f"SSDP-{source_ip}",
                    device_type=device_type,
                    manufacturer=manufacturer,
                    services=[device_info.get('nt', 'Unknown Service')],
                    protocol="SSDP",
                    timestamp=datetime.now()
                )
                
                self._add_device(device)
                
        except Exception as e:
            logger.debug(f"SSDP parsing error: {e}")

    def _parse_ssdp_server(self, server_str: str) -> tuple[str, str]:
        """Parse SSDP SERVER field to extract manufacturer and device type"""
        server_lower = server_str.lower()
        
        if 'upnp' in server_lower:
            if 'router' in server_lower:
                return 'Unknown', 'Router'
            elif 'media' in server_lower:
                return 'Unknown', 'Media Server'
            else:
                return 'Unknown', 'UPnP Device'
        
        # Manufacturer detection
        manufacturers = {
            'tplink': 'TP-Link',
            'linksys': 'Linksys',
            'netgear': 'Netgear',
            'dlink': 'D-Link',
            'asus': 'ASUS',
            'synology': 'Synology',
            'qnap': 'QNAP'
        }
        
        for key, manufacturer in manufacturers.items():
            if key in server_lower:
                return manufacturer, 'Network Device'
        
        return 'Unknown', 'UPnP Device'

    def _listen_dhcp(self):
        """Listen for DHCP traffic to fingerprint devices"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('', 67))  # DHCP server port
            
            while self.is_listening:
                try:
                    data, addr = sock.recvfrom(1024)
                    self._parse_dhcp_packet(data, addr[0])
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.debug(f"DHCP listening error: {e}")
                    
            sock.close()
        except PermissionError:
            logger.warning("DHCP listening requires root privileges")
        except Exception as e:
            logger.error(f"DHCP listener failed: {e}")

    def _parse_dhcp_packet(self, data: bytes, source_ip: str):
        """Parse DHCP packet to extract device information"""
        try:
            # Basic DHCP parsing - extract options
            if len(data) < 240:  # Minimum DHCP packet size
                return
            
            # Extract MAC address from DHCP packet
            mac_address = ':'.join(f'{b:02x}' for b in data[28:34])
            
            # Extract DHCP options
            options = data[240:]
            parameter_list = []
            
            i = 0
            while i < len(options):
                if options[i] == 55:  # Parameter Request List
                    length = options[i + 1]
                    param_list = options[i + 2:i + 2 + length]
                    parameter_list = [str(p) for p in param_list]
                    break
                elif options[i] == 255:  # End option
                    break
                else:
                    i += 1
            
            if parameter_list:
                param_string = ','.join(parameter_list)
                os_type = self.dhcp_fingerprints.get(param_string, 'Unknown')
                
                device = PassiveDevice(
                    mac_address=mac_address,
                    ip_address=source_ip,
                    hostname=f"DHCP-{mac_address}",
                    device_type=os_type,
                    manufacturer=self._infer_manufacturer_from_mac(mac_address),
                    services=['DHCP Client'],
                    protocol="DHCP",
                    timestamp=datetime.now()
                )
                
                self._add_device(device)
                
        except Exception as e:
            logger.debug(f"DHCP parsing error: {e}")

    def _listen_netbios(self):
        """Listen for NetBIOS name service requests"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('', 137))  # NetBIOS name service port
            
            sock.settimeout(1)
            
            while self.is_listening:
                try:
                    data, addr = sock.recvfrom(1024)
                    self._parse_netbios_packet(data, addr[0])
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.debug(f"NetBIOS listening error: {e}")
                    
            sock.close()
        except Exception as e:
            logger.error(f"NetBIOS listener failed: {e}")

    def _parse_netbios_packet(self, data: bytes, source_ip: str):
        """Parse NetBIOS packet to extract device information"""
        try:
            if len(data) < 12:
                return
            
            # Extract NetBIOS name (simplified)
            name_section = data[12:]
            if len(name_section) >= 16:
                name_bytes = name_section[:16]
                # NetBIOS names are 16 bytes, often padded with spaces
                name = name_bytes.decode('latin-1').strip()
                
                if name and name != 'WORKGROUP':
                    device = PassiveDevice(
                        mac_address="Unknown",
                        ip_address=source_ip,
                        hostname=name,
                        device_type="Windows Device",
                        manufacturer="Microsoft",
                        services=['NetBIOS'],
                        protocol="NetBIOS",
                        timestamp=datetime.now()
                    )
                    
                    self._add_device(device)
                    
        except Exception as e:
            logger.debug(f"NetBIOS parsing error: {e}")

    def _infer_manufacturer(self, service: str) -> str:
        """Infer manufacturer from service type"""
        service_lower = service.lower()
        
        if 'google' in service_lower:
            return 'Google'
        elif 'apple' in service_lower or 'airplay' in service_lower:
            return 'Apple'
        elif 'sonos' in service_lower:
            return 'Sonos'
        elif 'hap' in service_lower:
            return 'Apple'
        else:
            return 'Unknown'

    def _infer_manufacturer_from_mac(self, mac_address: str) -> str:
        """Infer manufacturer from MAC address OUI"""
        # Simplified OUI lookup - in practice, use a comprehensive OUI database
        oui = mac_address[:8].upper()
        
        oui_database = {
            '00:1B:44': 'Cisco',
            '00:24:FE': 'Huawei',
            '00:26:5A': 'Netgear',
            '00:1D:0F': 'Samsung',
            '00:1E:E1': 'Sony',
            '00:23:D4': 'Apple',
            '00:1C:B3': 'Belkin',
            '00:22:3F': 'Roku',
            '00:1F:5B': 'Google',
            '00:0C:29': 'VMware',
            '00:50:56': 'VMware',
            '00:1A:11': 'Google',
            '00:1E:65': 'Apple',
            '00:25:00': 'Apple',
            '00:26:BB': 'Apple'
        }
        
        return oui_database.get(oui, 'Unknown')

    def _add_device(self, device: PassiveDevice):
        """Add device to discovered devices list, avoiding duplicates"""
        # Check for existing device by IP or MAC
        existing_device = None
        for existing in self.discovered_devices:
            if (existing.ip_address == device.ip_address or 
                (device.mac_address != "Unknown" and existing.mac_address == device.mac_address)):
                existing_device = existing
                break
        
        if existing_device:
            # Update existing device with new information
            existing_device.services.extend([s for s in device.services if s not in existing_device.services])
            existing_device.timestamp = device.timestamp
            if existing_device.device_type == 'Unknown' and device.device_type != 'Unknown':
                existing_device.device_type = device.device_type
            if existing_device.manufacturer == 'Unknown' and device.manufacturer != 'Unknown':
                existing_device.manufacturer = device.manufacturer
        else:
            self.discovered_devices.append(device)

    def get_discovered_devices(self) -> List[Dict[str, Any]]:
        """Get list of discovered devices"""
        return [device.__dict__ for device in self.discovered_devices]

    def stop_scan(self):
        """Stop passive scanning"""
        self.is_listening = False