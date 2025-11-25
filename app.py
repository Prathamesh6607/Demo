from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, session
import pandas as pd
import numpy as np
import os
import json
from datetime import datetime
import threading
import time
import math
import subprocess
import signal

# Import your custom modules with fallbacks
try:
    from utils.network_scanner import NetworkScanner
except ImportError as e:
    print(f"NetworkScanner not available: {e}")
    # Create a fallback
    class NetworkScanner:
        def __init__(self):
            self.is_scanning = False
        
        def scan_network(self, target):
            return {'error': 'Network scanner not available'}
        
        def get_scan_progress(self):
            return {'status': 'error', 'current_operation': 'Scanner not available'}
        
        def get_local_network_ranges(self):
            return []

try:
    from utils.vulnerability_scanner import VulnerabilityScanner
except ImportError as e:
    print(f"VulnerabilityScanner not available: {e}")
    class VulnerabilityScanner:
        def search_cves(self, *args, **kwargs):
            return []
        def google_dorking(self, *args, **kwargs):
            return []

try:
    from utils.data_analyzer import DataAnalyzer
except ImportError as e:
    print(f"DataAnalyzer not available: {e}")
    class DataAnalyzer:
        def analyze_dataset(self, *args, **kwargs):
            return {'devices': []}
        def analyze_bluetooth_dataset(self, *args, **kwargs):
            return {'devices': []}
        def combine_datasets(self, *args, **kwargs):
            return []
        def analyze_protection(self, *args, **kwargs):
            return {}
        def map_devices_by_category(self, *args, **kwargs):
            return {}
        def detect_anomalies(self, *args, **kwargs):
            return {'total_anomalies': 0}
        def generate_alerts(self, *args, **kwargs):
            return []
        def suggest_response_actions(self, *args, **kwargs):
            return {}
        def generate_recovery_plan(self, *args, **kwargs):
            return {}
        def check_backup_status(self, *args, **kwargs):
            return {}
        def generate_nist_report(self, *args, **kwargs):
            return {}

try:
    from utils.devicehive_client import DeviceHiveClient
except ImportError as e:
    print(f"DeviceHiveClient not available: {e}")
    class DeviceHiveClient:
        def connect(self, *args, **kwargs):
            return True
        def get_devices(self, *args, **kwargs):
            return []
        def start_monitoring(self, *args, **kwargs):
            return {}

# NEW: Import Bluetooth scanner, database, and asset inventory with fallbacks
BLUETOOTH_AVAILABLE = False
ASSET_INVENTORY_AVAILABLE = False
device_db = None
asset_inventory = None
bluetooth_scanner = None

try:
    from utils.bluetooth_scanner import BluetoothScanner
    BLUETOOTH_AVAILABLE = True
except ImportError as e:
    print(f"BluetoothScanner not available: {e}")
    class BluetoothScanner:
        def __init__(self):
            self.discovered_devices = []
        def scan_bluetooth(self, *args, **kwargs):
            return []
        def get_scan_progress(self):
            return {'status': 'error'}
        def stop_scan(self):
            pass

try:
    from models.database import DeviceDatabase
    device_db = DeviceDatabase()
except ImportError as e:
    print(f"DeviceDatabase not available: {e}")
    class DeviceDatabase:
        def get_dashboard_stats(self):
            return {'network_devices': 0, 'bluetooth_devices': 0, 'high_risk_devices': 0, 'open_ports': 0}
        def get_combined_devices(self):
            return []
        def save_network_device(self, *args, **kwargs):
            return True
        def save_bluetooth_device(self, *args, **kwargs):
            return True
        def get_network_devices(self):
            return []
        def get_bluetooth_devices(self):
            return []

try:
    from models.device_models import IoTDevice, DeviceType, Protocol, DeviceStatus
    from utils.asset_inventory import AssetInventory
    ASSET_INVENTORY_AVAILABLE = True
    asset_inventory = AssetInventory()
except ImportError as e:
    print(f"Asset inventory components not available: {e}")
    # Create basic enums and classes
    from enum import Enum
    class DeviceType(Enum):
        CAMERA = "camera"
        SENSOR = "sensor"
        ROUTER = "router"
        LOCK = "lock"
        OTHER = "other"
    
    class Protocol(Enum):
        MQTT = "MQTT"
        COAP = "CoAP"
        HTTP = "HTTP"
        BLE = "BLE"
    
    class DeviceStatus(Enum):
        ACTIVE = "Active"
        INACTIVE = "Inactive"
        UNKNOWN = "Unknown"
    
    class IoTDevice:
        def __init__(self, **kwargs):
            pass
    
    class AssetInventory:
        def __init__(self):
            pass
        def add_device(self, *args, **kwargs):
            return True
        def delete_device(self, *args, **kwargs):
            return True
        def get_all_devices(self):
            return []
        def get_device_by_mac(self, *args, **kwargs):
            return None
        def get_statistics(self):
            return {'total_devices': 0, 'active_devices': 0, 'inactive_devices': 0, 'device_type_distribution': {}}

# NEW: Import Incident Response components
try:
    from models.incident_models import Incident, ResponsePlaybook
    from utils.incident_response import IncidentResponseService
    INCIDENT_RESPONSE_AVAILABLE = True
except ImportError as e:
    print(f"Incident response components not available: {e}")
    INCIDENT_RESPONSE_AVAILABLE = False
    
    # Fallback classes
    from enum import Enum
    class IncidentStatus(Enum):
        OPEN = "open"
        IN_PROGRESS = "in_progress"
        CONTAINED = "contained"
        RESOLVED = "resolved"
        CLOSED = "closed"
    
    class Incident:
        def __init__(self, **kwargs):
            pass
        def to_dict(self):
            return {}
    
    class ResponsePlaybook:
        def __init__(self, **kwargs):
            pass
        def to_dict(self):
            return {}
    
    class IncidentResponseService:
        def __init__(self, db):
            self.db = db
        def create_incident(self, *args, **kwargs):
            return Incident()
        def take_manual_action(self, *args, **kwargs):
            return {'status': 'error', 'message': 'Incident response not available'}

# NEW: Import enhanced components
try:
    from utils.passive_fingerprinter import PassiveFingerprinter
    PASSIVE_FINGERPRINTING_AVAILABLE = True
except ImportError as e:
    print(f"PassiveFingerprinter not available: {e}")
    PASSIVE_FINGERPRINTING_AVAILABLE = False
    class PassiveFingerprinter:
        def start_passive_scan(self, *args, **kwargs):
            return []
        def get_discovered_devices(self):
            return []

try:
    from utils.protocol_analyzer import ProtocolAnalyzer
    PROTOCOL_ANALYZER_AVAILABLE = True
except ImportError as e:
    print(f"ProtocolAnalyzer not available: {e}")
    PROTOCOL_ANALYZER_AVAILABLE = False
    class ProtocolAnalyzer:
        def comprehensive_protocol_analysis(self, *args, **kwargs):
            return {}

try:
    from utils.risk_engine import RiskEngine
    RISK_ENGINE_AVAILABLE = True
except ImportError as e:
    print(f"RiskEngine not available: {e}")
    RISK_ENGINE_AVAILABLE = False
    class RiskEngine:
        def calculate_device_risk(self, *args, **kwargs):
            return {'risk_score': 0, 'risk_level': 'Low'}
        def calculate_network_risk(self, *args, **kwargs):
            return {'network_risk_score': 0}

try:
    from utils.cve_lookup import CVELookup
    CVE_LOOKUP_AVAILABLE = True
except ImportError as e:
    print(f"CVELookup not available: {e}")
    CVE_LOOKUP_AVAILABLE = False
    class CVELookup:
        def search_iot_specific_cves(self, *args, **kwargs):
            return []

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'iot-nist-monitor-secret-key-2024'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'csv', 'txt', 'xml', 'json', 'xlsx'}

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize components
print("Initializing IoT NIST Monitor components...")
network_scanner = NetworkScanner()
vuln_scanner = VulnerabilityScanner()
data_analyzer = DataAnalyzer()
devicehive_client = DeviceHiveClient()

# NEW: Initialize Bluetooth, Database, and Asset Inventory components
if BLUETOOTH_AVAILABLE:
    bluetooth_scanner = BluetoothScanner()
    print("Bluetooth components initialized successfully!")
else:
    bluetooth_scanner = BluetoothScanner()  # Use fallback
    print("Bluetooth components not available - running in limited mode")

if device_db is None:
    device_db = DeviceDatabase()  # Use fallback

if asset_inventory is None:
    asset_inventory = AssetInventory()  # Use fallback

# NEW: Initialize Incident Response Service
if INCIDENT_RESPONSE_AVAILABLE:
    from IOT import db
    incident_response_service = IncidentResponseService(db)
    print("Incident Response components initialized successfully!")
else:
    # Create a mock database object for fallback
    class MockDB:
        class session:
            @staticmethod
            def add(obj): pass
            @staticmethod
            def commit(): pass
    incident_response_service = IncidentResponseService(MockDB())
    print("Incident Response components not available - running in limited mode")

# NEW: Initialize enhanced components
if PASSIVE_FINGERPRINTING_AVAILABLE:
    passive_fingerprinter = PassiveFingerprinter()
    print("Passive fingerprinting initialized successfully!")
else:
    passive_fingerprinter = PassiveFingerprinter()
    print("Passive fingerprinting not available - running in limited mode")

if PROTOCOL_ANALYZER_AVAILABLE:
    protocol_analyzer = ProtocolAnalyzer()
    print("Protocol analyzer initialized successfully!")
else:
    protocol_analyzer = ProtocolAnalyzer()
    print("Protocol analyzer not available - running in limited mode")

if RISK_ENGINE_AVAILABLE:
    risk_engine = RiskEngine()
    print("Risk engine initialized successfully!")
else:
    risk_engine = RiskEngine()
    print("Risk engine not available - running in limited mode")

if CVE_LOOKUP_AVAILABLE:
    cve_lookup = CVELookup()
    print("CVE lookup initialized successfully!")
else:
    cve_lookup = CVELookup()
    print("CVE lookup not available - running in limited mode")

print("All components initialized successfully!")

# Global variables for scan states
scan_states = {
    'network': {'active': False, 'progress': 0, 'devices': []},
    'bluetooth': {'active': False, 'progress': 0, 'devices': []}
}

# AWS IoT Simulation process
aws_iot_process = None

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def format_file_size(size_bytes):
    """Convert bytes to human readable format"""
    if size_bytes == 0:
        return "0B"
    size_names = ["B", "KB", "MB", "GB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"

def get_dashboard_stats():
    """Get dashboard statistics with fallback if database not available"""
    if device_db:
        return device_db.get_dashboard_stats()
    else:
        return {
            'network_devices': 0,
            'bluetooth_devices': 0,
            'high_risk_devices': 0,
            'open_ports': 0
        }

def get_combined_devices():
    """Get combined devices with fallback"""
    if device_db:
        return device_db.get_combined_devices()[:10]
    else:
        return []

def save_network_devices(devices):
    """Save network devices to database if available"""
    if device_db and devices:
        for device in devices:
            device_db.save_network_device(device)
    return devices

def save_bluetooth_devices(devices):
    """Save Bluetooth devices to database if available"""
    if device_db and devices and not isinstance(devices, dict):
        for device in devices:
            device_db.save_bluetooth_device(device)
    return devices

def get_network_devices_from_db():
    """Get network devices from database"""
    if device_db:
        return device_db.get_network_devices()
    return []

def get_bluetooth_devices_from_db():
    """Get Bluetooth devices from database"""
    if device_db:
        return device_db.get_bluetooth_devices()
    return []

def get_asset_statistics():
    """Get asset inventory statistics"""
    if asset_inventory:
        try:
            return asset_inventory.get_statistics()
        except Exception as e:
            print(f"Error getting asset statistics: {e}")
    
    return {
        'total_devices': 0,
        'active_devices': 0,
        'inactive_devices': 0,
        'device_type_distribution': {},
        'protocol_distribution': {}
    }

def create_aws_iot_simulation_script():
    """Create the AWS IoT simulation script file"""
    script_content = '''#!/usr/bin/env python3
"""
Simple AWS IoT MQTT publisher (robust settings)
Replace the cert/key/ca paths below with the actual file locations on your system.
Endpoint: a3vlu21e6pc561-ats.iot.eu-north-1.amazonaws.com
"""

import os
import time
import json
import signal
import sys
import subprocess
import threading
from AWSIoTPythonSDK.MQTTLib import AWSIoTMQTTClient

# --- Configuration: update these paths ---
AWS_IOT_ENDPOINT = "a3vlu21e6pc561-ats.iot.eu-north-1.amazonaws.com"  # your endpoint
AWS_IOT_PORT = 8883

# Use absolute or expanded paths. Example: r"C:\\\\path\\\\to\\\\cert.pem.crt" on Windows
ROOT_CA_PATH = os.path.expanduser(r"C:\\Users\\prath\\OneDrive\\Desktop\\iot_nist_monitor\\iot_nist_monitor\\IOT\\connect_device_package\\root-CA.crt")
PRIVATE_KEY_PATH = os.path.expanduser(r"C:\\Users\\prath\\OneDrive\\Desktop\\iot_nist_monitor\\iot_nist_monitor\\IOT\\connect_device_package\\demothing.private.key")
CERTIFICATE_PATH = os.path.expanduser(r"C:\\Users\\prath\\OneDrive\\Desktop\\iot_nist_monitor\\iot_nist_monitor\\IOT\\connect_device_package\\demothing.cert.pem")

# Path to start.ps1 script
START_PS1_PATH = os.path.expanduser(r"C:\\Users\\prath\\OneDrive\\Desktop\\iot_nist_monitor\\iot_nist_monitor\\start.ps1")

# MQTT settings
CLIENT_ID = "iotconsole-37f61f05-feb3-4d61-96e9-f114654b09e81"  # make unique if running multiple clients
TOPIC = "iot/security/telemetry"
PUBLISH_INTERVAL = 5  # seconds

# Global variables
running = True
ps_process = None

# --- Safety checks on files ---
for p in (ROOT_CA_PATH, PRIVATE_KEY_PATH, CERTIFICATE_PATH):
    if not os.path.isfile(p):
        print(f"[ERROR] Certificate/key file not found: {p}")
        print("Update ROOT_CA_PATH / PRIVATE_KEY_PATH / CERTIFICATE_PATH to correct files and try again.")
        sys.exit(1)

# Check if start.ps1 exists
if not os.path.isfile(START_PS1_PATH):
    print(f"[WARNING] start.ps1 not found at: {START_PS1_PATH}")
    print("The simulation will run without starting the PowerShell script.")

def start_powershell_script():
    """Start the start.ps1 script in the background with execution policy"""
    global ps_process
    try:
        print(f"Starting PowerShell script: {START_PS1_PATH}")
        
        # PowerShell command to set execution policy and run the script
        powershell_cmd = [
            "powershell.exe",
            "-ExecutionPolicy", "Bypass",
            "-File", START_PS1_PATH
        ]
        
        # Start the process in background (no console window)
        ps_process = subprocess.Popen(
            powershell_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW  # Run in background without window
        )
        
        print("PowerShell script started successfully in background")
        
        # Start a thread to monitor the process output (optional)
        def monitor_output():
            while ps_process and ps_process.poll() is None:
                try:
                    output = ps_process.stdout.readline().decode('utf-8', errors='ignore').strip()
                    if output:
                        print(f"[PowerShell] {output}")
                except:
                    pass
        
        output_thread = threading.Thread(target=monitor_output, daemon=True)
        output_thread.start()
        
    except Exception as e:
        print(f"[ERROR] Failed to start PowerShell script: {e}")

def stop_powershell_script():
    """Stop the PowerShell script when simulation ends"""
    global ps_process
    if ps_process and ps_process.poll() is None:
        print("Stopping PowerShell script...")
        try:
            ps_process.terminate()
            ps_process.wait(timeout=5)
            print("PowerShell script stopped successfully")
        except subprocess.TimeoutExpired:
            print("Force killing PowerShell script...")
            ps_process.kill()
        except Exception as e:
            print(f"[WARNING] Error stopping PowerShell script: {e}")

# Graceful shutdown support
def _signal_handler(sig, frame):
    global running
    print("\\nReceived termination signal, shutting down gracefully...")
    running = False
    stop_powershell_script()

signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)

# --- Start PowerShell script in background ---
start_powershell_script()

# --- Create and configure client ---
mqtt_client = AWSIoTMQTTClient(CLIENT_ID)

# Endpoint and credentials (TLS)
mqtt_client.configureEndpoint(AWS_IOT_ENDPOINT, AWS_IOT_PORT)
mqtt_client.configureCredentials(ROOT_CA_PATH, PRIVATE_KEY_PATH, CERTIFICATE_PATH)

# Reconnect/backoff configuration
mqtt_client.configureAutoReconnectBackoffTime(1, 32, 20)

# Offline publish queueing: -1 means infinite
mqtt_client.configureOfflinePublishQueueing(-1)  # queue indefinitely when offline
mqtt_client.configureDrainingFrequency(2)  # Hz - how fast to drain the queue when back online
mqtt_client.configureConnectDisconnectTimeout(10)  # seconds
mqtt_client.configureMQTTOperationTimeout(5)  # seconds

# Optional: enable TLS mutual auth log info (comment out to reduce noise)
# import logging
# logging.basicConfig(level=logging.DEBUG)

# Connect
print(f"Connecting to AWS IoT endpoint: {AWS_IOT_ENDPOINT}:{AWS_IOT_PORT} ...")
try:
    mqtt_client.connect()
except Exception as e:
    print(f"[ERROR] Failed to connect: {e}")
    stop_powershell_script()
    sys.exit(1)

print("Connected. Starting publishing loop, Ctrl-C to stop.")

# --- Publishing loop ---
def generate_payload(device_id="sensor-001"):
    # simple pseudo-random-ish values using time
    t = time.time()
    # smoother variation than modulo
    temperature = 25.0 + (3.0 * ( (t % 60) / 60.0 ))  # 25..28 over a minute
    humidity = 40.0 + (5.0 * ( (t % 30) / 30.0 ))     # 40..45 over 30s
    return {
        "device_id": device_id,
        "temperature": round(temperature, 2),
        "humidity": round(humidity, 2),
        "timestamp": int(t)
    }

try:
    while running:
        payload = generate_payload("sensor-001")
        payload_json = json.dumps(payload)
        try:
            mqtt_client.publish(TOPIC, payload_json, 1)  # QoS 1
            print(f"Published to {TOPIC}: {payload_json}")
        except Exception as pub_e:
            print(f"[WARN] Publish failed: {pub_e} (will retry or queue depending on connection)")

        # Sleep with responsiveness to shutdown
        slept = 0.0
        while running and slept < PUBLISH_INTERVAL:
            time.sleep(0.2)
            slept += 0.2

finally:
    try:
        print("Disconnecting MQTT client...")
        mqtt_client.disconnect()
    except Exception as e:
        print(f"[WARN] Error during disconnect: {e}")
    
    stop_powershell_script()
    print("Shutdown complete.")
'''

    # Create scripts directory if it doesn't exist
    scripts_dir = os.path.join(os.path.dirname(__file__), 'scripts')
    os.makedirs(scripts_dir, exist_ok=True)
    
    # Write the script file
    script_path = os.path.join(scripts_dir, 'aws_iot_simulation.py')
    with open(script_path, 'w') as f:
        f.write(script_content)
    
    # Make it executable (Unix-like systems)
    try:
        os.chmod(script_path, 0o755)
    except:
        pass  # Ignore on Windows
    
    return script_path

@app.route('/monitoring-status')
def monitoring_status():
    # Return monitoring status data
    return {
        'status': 'running',
        'devices_monitored': len(get_network_devices_from_db()) + len(get_bluetooth_devices_from_db()),
        'timestamp': datetime.now().isoformat()  
    }

@app.route('/')
def index():
    """Home page with dashboard"""
    try:
        # Try to load the latest CSV from uploads/
        uploaded_file = get_latest_upload()
        stats = {'network_devices': 0, 'bluetooth_devices': 0, 'high_risk_devices': 0, 'open_ports': 0}
        recent_devices = []
        csv_data = None
        if uploaded_file and uploaded_file.endswith('.csv'):
            try:
                df = pd.read_csv(uploaded_file)
                csv_data = df.to_dict(orient='records')
                # Dynamically calculate dashboard stats based on available fields
                # Network Devices: count rows where Machine_Type or device_type contains 'network', 'router', 'gateway', etc.
                if 'Machine_Type' in df.columns:
                    stats['network_devices'] = df['Machine_Type'].str.contains('network|router|gateway|switch|CNC|Vision|Chiller|Controller|Screwdriver|Labeler|System|Belt|Robot|Sensor', case=False, na=False).sum()
                elif 'device_type' in df.columns:
                    stats['network_devices'] = df['device_type'].str.contains('network|router|gateway|switch', case=False, na=False).sum()
                # Bluetooth Devices: count rows where Machine_Type or device_type contains 'bluetooth' or 'BLE'
                if 'Machine_Type' in df.columns:
                    stats['bluetooth_devices'] = df['Machine_Type'].str.contains('bluetooth|ble', case=False, na=False).sum()
                elif 'device_type' in df.columns:
                    stats['bluetooth_devices'] = df['device_type'].str.contains('bluetooth|ble', case=False, na=False).sum()
                # High Risk Devices: count rows where Failure_Within_7_Days is True or risk_level is 'high'
                if 'Failure_Within_7_Days' in df.columns:
                    stats['high_risk_devices'] = df['Failure_Within_7_Days'].astype(str).str.lower().eq('true').sum()
                elif 'risk_level' in df.columns:
                    stats['high_risk_devices'] = df['risk_level'].astype(str).str.lower().eq('high').sum()
                # Open Ports: sum open_ports column if present, else 0
                if 'open_ports' in df.columns:
                    try:
                        stats['open_ports'] = df['open_ports'].astype(float).sum()
                    except Exception:
                        stats['open_ports'] = 0
                else:
                    stats['open_ports'] = 0
                # Show up to 10 recent devices
                recent_devices = csv_data[:10]
            except Exception as e:
                print(f"CSV parse error: {e}")
        else:
            # Fallback to existing logic if no CSV
            stats = get_dashboard_stats()
            recent_devices = get_combined_devices()
        return render_template('index.html', 
                             stats=stats,
                             recent_devices=recent_devices,
                             csv_data=csv_data)
    except Exception as e:
        print(f"Dashboard error: {e}")
        return render_template('index.html', 
                             stats={'network_devices': 0, 'bluetooth_devices': 0, 'high_risk_devices': 0, 'open_ports': 0},
                             recent_devices=[],
                             csv_data=None)

@app.route('/identify', methods=['GET', 'POST'])
def identify():
    """NIST Phase 1: Identify - Asset Discovery & Inventory Management"""
    try:
        network_results = []
        bluetooth_results = []
        combined_results = []
        asset_stats = {}
        
        if request.method == 'POST':
            # Network Scan
            if 'network_scan' in request.form:
                target = request.form.get('network_range', '').strip()
                if not target:
                    flash('❌ Please enter a network range (CIDR notation)', 'error')
                else:
                    print(f"Starting network scan for: {target}")
                    scan_result = network_scanner.scan_network(target)
                    
                    if 'error' in scan_result:
                        flash(f'❌ Scan error: {scan_result["error"]}', 'error')
                    else:
                        # Save network devices to database
                        network_devices = scan_result.get('devices', [])
                        network_results = save_network_devices(network_devices)
                        
                        flash(f'🔍 Network scan completed for {target}. Found {len(network_results)} devices', 'success')
            
            # Bluetooth Scan
            elif 'bluetooth_scan' in request.form:
                if not BLUETOOTH_AVAILABLE:
                    flash('❌ Bluetooth scanning is not available on this system', 'error')
                else:
                    print("Starting Bluetooth scan...")
                    try:
                        scan_duration = int(request.form.get('scan_duration', 30))
                        bluetooth_results = bluetooth_scanner.scan_bluetooth(duration=scan_duration)
                        
                        if 'error' in bluetooth_results:
                            flash(f'❌ Bluetooth scan failed: {bluetooth_results["error"]}', 'error')
                        else:
                            # Save Bluetooth devices to database
                            bluetooth_results = save_bluetooth_devices(bluetooth_results)
                            
                            flash(f'📱 Bluetooth scan completed. Found {len(bluetooth_results)} devices', 'success')
                            
                    except Exception as e:
                        print(f"Bluetooth scan error: {e}")
                        flash(f'❌ Bluetooth scan failed: {str(e)}', 'error')
            
            # Manual Device Addition
            elif 'add_device' in request.form:
                try:
                    device_data = {
                        'device_name': request.form.get('device_name', '').strip(),
                        'mac_address': request.form.get('mac_address', '').strip(),
                        'ip_address': request.form.get('ip_address', '').strip(),
                        'manufacturer': request.form.get('manufacturer', '').strip(),
                        'device_type': request.form.get('device_type', 'other'),
                        'firmware_version': request.form.get('firmware_version', 'Unknown'),
                        'protocols': request.form.getlist('protocols'),
                        'os_info': request.form.get('os_info', ''),
                        'location': request.form.get('location', ''),
                        'description': request.form.get('description', '')
                    }
                    
                    # Validate required fields
                    if not device_data['device_name'] or not device_data['mac_address']:
                        flash('❌ Device Name and MAC Address are required', 'error')
                    else:
                        # Create device object and save to asset inventory
                        device = IoTDevice(
                            device_name=device_data['device_name'],
                            mac_address=device_data['mac_address'],
                            ip_address=device_data['ip_address'],
                            manufacturer=device_data['manufacturer'],
                            device_type=DeviceType(device_data['device_type']),
                            firmware_version=device_data['firmware_version'],
                            protocols=[Protocol(p) for p in device_data['protocols'] if p in [proto.value for proto in Protocol]]
                        )
                        
                        if asset_inventory:
                            success = asset_inventory.add_device(device)
                            if success:
                                flash(f'✅ Device "{device_data["device_name"]}" added successfully', 'success')
                            else:
                                flash('❌ Failed to save device to asset inventory', 'error')
                        else:
                            flash('✅ Device added (asset inventory not available)', 'success')
                            
                except Exception as e:
                    flash(f'❌ Failed to add device: {str(e)}', 'error')
            
            # Delete Device
            elif 'delete_device' in request.form:
                mac_address = request.form.get('mac_address', '').strip()
                if mac_address and asset_inventory:
                    success = asset_inventory.delete_device(mac_address)
                    if success:
                        flash(f'✅ Device with MAC {mac_address} deleted successfully', 'success')
                    else:
                        flash('❌ Device not found or deletion failed', 'error')
                else:
                    flash('❌ MAC address is required', 'error')
            
            # Network Dataset Upload
            elif 'upload_network_dataset' in request.form:
                if 'network_dataset' not in request.files:
                    flash('❌ No network dataset file selected', 'error')
                    return redirect(request.url)
                
                file = request.files['network_dataset']
                if file.filename == '':
                    flash('❌ No network dataset file selected', 'error')
                    return redirect(request.url)
                
                if file and allowed_file(file.filename):
                    try:
                        # Check file size
                        file.seek(0, 2)  # Seek to end to get size
                        file_size = file.tell()
                        file.seek(0)  # Reset file pointer
                        
                        if file_size > app.config['MAX_CONTENT_LENGTH']:
                            flash(f'❌ File size ({format_file_size(file_size)}) exceeds maximum allowed ({format_file_size(app.config["MAX_CONTENT_LENGTH"])})', 'error')
                            return redirect(request.url)
                        
                        filename = f"network_dataset_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(filepath)
                        
                        # Analyze the dataset
                        analysis_results = data_analyzer.analyze_dataset(filepath)
                        if 'error' in analysis_results:
                            flash(f'❌ Network dataset analysis failed: {analysis_results["error"]}', 'error')
                        else:
                            network_results = analysis_results.get('devices', [])
                            
                            # Save to database
                            network_results = save_network_devices(network_results)
                            
                            flash(f'📊 Network dataset uploaded and analyzed. Found {len(network_results)} devices', 'success')
                            
                    except Exception as e:
                        flash(f'❌ Network file upload failed: {str(e)}', 'error')
                else:
                    flash('❌ Please upload a valid file (CSV, TXT, XML, JSON, XLSX)', 'error')
            
            # Bluetooth Dataset Upload
            elif 'upload_bluetooth_dataset' in request.form:
                if 'bluetooth_dataset' not in request.files:
                    flash('❌ No bluetooth dataset file selected', 'error')
                    return redirect(request.url)
                
                file = request.files['bluetooth_dataset']
                if file.filename == '':
                    flash('❌ No bluetooth dataset file selected', 'error')
                    return redirect(request.url)
                
                if file and allowed_file(file.filename):
                    try:
                        # Check file size
                        file.seek(0, 2)  # Seek to end to get size
                        file_size = file.tell()
                        file.seek(0)  # Reset file pointer
                        
                        if file_size > app.config['MAX_CONTENT_LENGTH']:
                            flash(f'❌ File size ({format_file_size(file_size)}) exceeds maximum allowed ({format_file_size(app.config["MAX_CONTENT_LENGTH"])})', 'error')
                            return redirect(request.url)
                        
                        filename = f"bluetooth_dataset_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(filepath)
                        
                        # Analyze the bluetooth dataset
                        analysis_results = data_analyzer.analyze_bluetooth_dataset(filepath)
                        if 'error' in analysis_results:
                            flash(f'❌ Bluetooth dataset analysis failed: {analysis_results["error"]}', 'error')
                        else:
                            bluetooth_results = analysis_results.get('devices', [])
                            
                            # Save to database
                            bluetooth_results = save_bluetooth_devices(bluetooth_results)
                            
                            flash(f'📊 Bluetooth dataset uploaded and analyzed. Found {len(bluetooth_results)} devices', 'success')
                            
                    except Exception as e:
                        flash(f'❌ Bluetooth file upload failed: {str(e)}', 'error')
                else:
                    flash('❌ Please upload a valid file (CSV, TXT, XML, JSON, XLSX)', 'error')
        
        # Get devices from database and asset inventory
        network_results = get_network_devices_from_db()
        bluetooth_results = get_bluetooth_devices_from_db()

        # --- Add devices from latest CSV ---
        uploaded_file = get_latest_upload()
        csv_network = []
        csv_bluetooth = []
        if uploaded_file and uploaded_file.endswith('.csv'):
            import pandas as pd
            try:
                df = pd.read_csv(uploaded_file)
                if 'Machine_Type' in df.columns:
                    csv_network = df[df['Machine_Type'].str.contains('network|router|gateway|switch|CNC|Vision|Chiller|Controller|Screwdriver|Labeler|System|Belt|Robot|Sensor', case=False, na=False)].to_dict(orient='records')
                    csv_bluetooth = df[df['Machine_Type'].str.contains('bluetooth|ble', case=False, na=False)].to_dict(orient='records')
                elif 'device_type' in df.columns:
                    csv_network = df[df['device_type'].str.contains('network|router|gateway|switch', case=False, na=False)].to_dict(orient='records')
                    csv_bluetooth = df[df['device_type'].str.contains('bluetooth|ble', case=False, na=False)].to_dict(orient='records')
            except Exception as e:
                print(f"CSV parse error (identify): {e}")
        # Merge CSV devices with scan results
        network_results.extend(csv_network)
        bluetooth_results.extend(csv_bluetooth)
        # --- End CSV merge ---

        # Get asset inventory devices
        if asset_inventory:
            try:
                asset_devices = asset_inventory.get_all_devices()
                network_results.extend(asset_devices)
            except Exception as e:
                print(f"Error getting asset inventory devices: {e}")

        # Get asset inventory statistics
        asset_stats = get_asset_statistics()

        # Combine results for unified display
        try:
            combined_results = data_analyzer.combine_datasets(network_results, bluetooth_results)
        except Exception as e:
            print(f"Combining datasets error: {e}")
            combined_results = []

        # Get current scan progress
        scan_progress = network_scanner.get_scan_progress()

        # Get local network ranges for dropdown
        local_networks = network_scanner.get_local_network_ranges()

        # Get dashboard stats for the template
        stats = get_dashboard_stats()

        return render_template('identify.html', 
                             scan_progress=scan_progress,
                             local_networks=local_networks,
                             network_results=network_results,
                             bluetooth_results=bluetooth_results,
                             combined_results=combined_results,
                             asset_stats=asset_stats,
                             stats=stats,  # Add this line to pass stats to template
                             device_types=[dt.value for dt in DeviceType],
                             protocols=[p.value for p in Protocol],
                             bluetooth_available=BLUETOOTH_AVAILABLE)
                             
    except Exception as e:
        print(f"Error in identify route: {e}")
        flash(f'❌ System error: {str(e)}', 'error')
        # Provide default stats in case of error
        stats = get_dashboard_stats()
        return render_template('identify.html', 
                             scan_progress={'status': 'error', 'current_operation': str(e)},
                             local_networks=[],
                             network_results=[],
                             bluetooth_results=[],
                             combined_results=[],
                             asset_stats={},
                             stats=stats,  # Add this line
                             device_types=[dt.value for dt in DeviceType],
                             protocols=[p.value for p in Protocol],
                             bluetooth_available=BLUETOOTH_AVAILABLE)

# NEW: Enhanced device detail route
@app.route('/identify/device/<mac_address>')
def device_detail(mac_address):
    """Enhanced device detail page"""
    try:
        device = None
        
        # Try to get device from asset inventory first
        if asset_inventory:
            device = asset_inventory.get_device_by_mac(mac_address)
        
        # If not found, try database
        if not device and device_db:
            network_devices = device_db.get_network_devices()
            for dev in network_devices:
                if dev.get('mac_address') == mac_address:
                    device = dev
                    break
        
        if not device:
            flash('❌ Device not found', 'error')
            return redirect(url_for('identify'))
        
        # Enhance device with risk analysis if available
        if RISK_ENGINE_AVAILABLE:
            risk_analysis = risk_engine.calculate_device_risk(device)
            device.update(risk_analysis)
        
        # Get vulnerabilities if available
        if CVE_LOOKUP_AVAILABLE:
            vulnerabilities = cve_lookup.search_iot_specific_cves(device)
            device['vulnerabilities'] = vulnerabilities
        
        return render_template('device_detail.html', device=device)
        
    except Exception as e:
        flash(f'❌ Error loading device details: {str(e)}', 'error')
        return redirect(url_for('identify'))

@app.route('/identify/device/<mac_address>', methods=['DELETE'])
def delete_device(mac_address):
    """Delete specific device"""
    try:
        if asset_inventory:
            success = asset_inventory.delete_device(mac_address)
            if success:
                return jsonify({'success': True, 'message': 'Device deleted successfully'})
            else:
                return jsonify({'success': False, 'error': 'Device not found'})
        else:
            return jsonify({'success': False, 'error': 'Asset inventory not available'})
                
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# NEW: Enhanced device analysis routes
@app.route('/identify/device/<mac_address>/analyze', methods=['POST'])
def analyze_device(mac_address):
    """Analyze specific device for vulnerabilities and risks"""
    try:
        device = None
        
        # Get device data
        if asset_inventory:
            device = asset_inventory.get_device_by_mac(mac_address)
        
        if not device:
            return jsonify({'success': False, 'error': 'Device not found'})
        
        # Perform comprehensive analysis
        analysis_results = {}
        
        # Risk analysis
        if RISK_ENGINE_AVAILABLE:
            risk_analysis = risk_engine.calculate_device_risk(device)
            analysis_results.update(risk_analysis)
        
        # Vulnerability analysis
        if CVE_LOOKUP_AVAILABLE:
            vulnerabilities = cve_lookup.search_iot_specific_cves(device)
            analysis_results['vulnerabilities'] = [v.__dict__ for v in vulnerabilities]
        
        # Protocol analysis
        if PROTOCOL_ANALYZER_AVAILABLE and device.get('ip_address'):
            protocol_analysis = protocol_analyzer.comprehensive_protocol_analysis(device['ip_address'])
            analysis_results['protocol_analysis'] = protocol_analysis
        
        # Update device in database with analysis results
        if device_db and analysis_results:
            # This would update the device with analysis results
            pass
        
        return jsonify({
            'success': True, 
            'message': 'Device analysis completed',
            'analysis': analysis_results
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/identify/device/<mac_address>/quarantine', methods=['POST'])
def quarantine_device(mac_address):
    """Quarantine a device"""
    try:
        if asset_inventory:
            success = asset_inventory.quarantine_device(mac_address)
            if success:
                return jsonify({'success': True, 'message': 'Device quarantined successfully'})
            else:
                return jsonify({'success': False, 'error': 'Failed to quarantine device'})
        else:
            return jsonify({'success': False, 'error': 'Asset inventory not available'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/identify/device/<mac_address>/release', methods=['POST'])
def release_device(mac_address):
    """Release device from quarantine"""
    try:
        # This would be implemented in the asset inventory
        # For now, return success
        return jsonify({'success': True, 'message': 'Device released from quarantine'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# NEW: Passive scanning route
@app.route('/identify/passive_scan', methods=['POST'])
def passive_scan():
    """Perform passive network fingerprinting"""
    try:
        if not PASSIVE_FINGERPRINTING_AVAILABLE:
            return jsonify({'success': False, 'error': 'Passive fingerprinting not available'})
        
        duration = int(request.json.get('duration', 300))  # Default 5 minutes
        
        # Start passive scan in background thread
        def scan_thread():
            try:
                devices = passive_fingerprinter.start_passive_scan(duration=duration)
                # Save discovered devices
                for device in devices:
                    if device_db:
                        device_db.save_network_device(device)
            except Exception as e:
                print(f"Passive scan error: {e}")
        
        thread = threading.Thread(target=scan_thread)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True, 
            'message': f'Passive scan started for {duration} seconds',
            'devices': passive_fingerprinter.get_discovered_devices()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# NEW: Bulk analysis route
@app.route('/identify/bulk_analyze', methods=['POST'])
def bulk_analyze():
    """Perform bulk analysis on multiple devices"""
    try:
        data = request.json
        device_macs = data.get('devices', [])
        
        if not device_macs:
            return jsonify({'success': False, 'error': 'No devices specified'})
        
        analysis_results = []
        
        for mac in device_macs:
            # Get device data
            device = None
            if asset_inventory:
                device = asset_inventory.get_device_by_mac(mac)
            
            if device:
                # Perform risk analysis
                if RISK_ENGINE_AVAILABLE:
                    risk_analysis = risk_engine.calculate_device_risk(device)
                    device.update(risk_analysis)
                
                analysis_results.append({
                    'mac_address': mac,
                    'device_name': device.get('device_name', 'Unknown'),
                    'risk_score': device.get('risk_score', 0),
                    'risk_level': device.get('risk_level', 'Low')
                })
        
        return jsonify({
            'success': True,
            'message': f'Bulk analysis completed for {len(analysis_results)} devices',
            'processed': len(analysis_results),
            'results': analysis_results
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/identify/statistics')
def identify_statistics():
    """Get asset inventory statistics"""
    try:
        stats = get_asset_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/identify/export')
def export_asset_inventory():
    """Export asset inventory to CSV"""
    try:
        import csv
        from io import StringIO
        
        # Get all devices from asset inventory
        if asset_inventory:
            all_devices = asset_inventory.get_all_devices()
        else:
            all_devices = []
        
        # Also get from database
        network_devices = get_network_devices_from_db()
        bluetooth_devices = get_bluetooth_devices_from_db()
        all_devices.extend(network_devices + bluetooth_devices)
        
        # Create CSV in memory
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Device Name', 'MAC Address', 'IP Address', 'Manufacturer', 
            'Device Type', 'Firmware Version', 'Protocols', 'Last Seen', 
            'Status', 'First Seen'
        ])
        
        # Write data
        for device in all_devices:
            writer.writerow([
                device.get('device_name', ''),
                device.get('mac_address', ''),
                device.get('ip_address', ''),
                device.get('manufacturer', ''),
                device.get('device_type', ''),
                device.get('firmware_version', ''),
                ', '.join(device.get('protocols', [])),
                device.get('last_seen', ''),
                device.get('status', ''),
                device.get('first_seen', '')
            ])
        
        # Return as downloadable file
        from flask import send_file
        import io
        
        file_obj = io.BytesIO(output.getvalue().encode('utf-8'))
        filename = f"asset_inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        return send_file(
            file_obj,
            as_attachment=True,
            download_name=filename,
            mimetype='text/csv'
        )
        
    except Exception as e:
        flash(f'❌ Export failed: {str(e)}', 'error')
        return redirect(url_for('identify'))

@app.route('/network_scan_progress')
def network_scan_progress():
    """API endpoint to get current network scan progress"""
    try:
        progress = network_scanner.get_scan_progress()
        # Get devices from database for live display
        network_devices = get_network_devices_from_db()
        progress['devices'] = network_devices[:10]  # Limit for live display
        return jsonify(progress)
    except Exception as e:
        return jsonify({'status': 'error', 'current_operation': str(e), 'devices': []})

@app.route('/bluetooth_scan_progress')
def bluetooth_scan_progress():
    """API endpoint to get current bluetooth scan progress"""
    try:
        if not BLUETOOTH_AVAILABLE:
            return jsonify({'status': 'error', 'current_operation': 'Bluetooth not available', 'devices': []})
        
        progress = bluetooth_scanner.get_scan_progress()
        # Get devices from scanner or database for live display
        if hasattr(bluetooth_scanner, 'discovered_devices') and bluetooth_scanner.discovered_devices:
            progress['devices'] = bluetooth_scanner.discovered_devices[:10]
        else:
            bluetooth_devices = get_bluetooth_devices_from_db()
            progress['devices'] = bluetooth_devices[:10]
        return jsonify(progress)
    except Exception as e:
        return jsonify({'status': 'error', 'current_operation': str(e), 'devices': []})

@app.route('/start_network_scan', methods=['POST'])
def start_network_scan():
    """API endpoint to start network scan"""
    try:
        target = request.form.get('network_range', '').strip()
        if not target:
            return jsonify({'success': False, 'error': 'Network range is required'})
        
        # Start scan in background thread
        def scan_thread():
            try:
                scan_result = network_scanner.scan_network(target)
                if 'devices' in scan_result:
                    save_network_devices(scan_result['devices'])
                scan_states['network']['active'] = False
            except Exception as e:
                print(f"Scan thread error: {e}")
                scan_states['network']['active'] = False
        
        scan_states['network']['active'] = True
        thread = threading.Thread(target=scan_thread)
        thread.daemon = True
        thread.start()
        
        return jsonify({'success': True, 'message': f'Network scan started for {target}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/start_bluetooth_scan', methods=['POST'])
def start_bluetooth_scan():
    """API endpoint to start bluetooth scan"""
    try:
        if not BLUETOOTH_AVAILABLE:
            return jsonify({'success': False, 'error': 'Bluetooth scanning not available'})
        
        scan_duration = int(request.form.get('scan_duration', 30))
        
        # Start scan in background thread
        def scan_thread():
            try:
                bluetooth_results = bluetooth_scanner.scan_bluetooth(duration=scan_duration)
                save_bluetooth_devices(bluetooth_results)
            except Exception as e:
                print(f"Bluetooth scan thread error: {e}")
        
        thread = threading.Thread(target=scan_thread)
        thread.daemon = True
        thread.start()
        
        return jsonify({'success': True, 'message': f'Bluetooth scan started for {scan_duration} seconds'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/stop_network_scan')
def stop_network_scan():
    """API endpoint to stop network scan"""
    try:
        network_scanner.is_scanning = False
        scan_states['network']['active'] = False
        return jsonify({"status": "stopped", "message": "Network scan stopped successfully"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/stop_bluetooth_scan')
def stop_bluetooth_scan():
    """API endpoint to stop bluetooth scan"""
    try:
        if not BLUETOOTH_AVAILABLE:
            return jsonify({"status": "error", "message": "Bluetooth not available"})
        
        bluetooth_scanner.stop_scan()
        scan_states['bluetooth']['active'] = False
        return jsonify({"status": "stopped", "message": "Bluetooth scan stopped successfully"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/protect', methods=['GET', 'POST'])
def protect():
    """NIST Phase 2: Protect - Security Controls Analysis & Ansible Config Generation"""
    try:
        protection_analysis = None
        device_mapping = None
        ansible_systems = get_ansible_supported_systems()
        # --- Dynamic CSV stats logic ---
        stats = {'network_devices': 0, 'bluetooth_devices': 0, 'high_risk_devices': 0, 'open_ports': 0}
        recent_devices = []
        csv_data = None
        uploaded_file = get_latest_upload()
        if uploaded_file and uploaded_file.endswith('.csv'):
            try:
                df = pd.read_csv(uploaded_file)
                csv_data = df.to_dict(orient='records')
                # Network Devices
                if 'Machine_Type' in df.columns:
                    stats['network_devices'] = df['Machine_Type'].str.contains('network|router|gateway|switch|CNC|Vision|Chiller|Controller|Screwdriver|Labeler|System|Belt|Robot|Sensor', case=False, na=False).sum()
                elif 'device_type' in df.columns:
                    stats['network_devices'] = df['device_type'].str.contains('network|router|gateway|switch', case=False, na=False).sum()
                # Bluetooth Devices
                if 'Machine_Type' in df.columns:
                    stats['bluetooth_devices'] = df['Machine_Type'].str.contains('bluetooth|ble', case=False, na=False).sum()
                elif 'device_type' in df.columns:
                    stats['bluetooth_devices'] = df['device_type'].str.contains('bluetooth|ble', case=False, na=False).sum()
                # High Risk Devices
                if 'Failure_Within_7_Days' in df.columns:
                    stats['high_risk_devices'] = df['Failure_Within_7_Days'].astype(str).str.lower().eq('true').sum()
                elif 'risk_level' in df.columns:
                    stats['high_risk_devices'] = df['risk_level'].astype(str).str.lower().eq('high').sum()
                # Open Ports
                if 'open_ports' in df.columns:
                    try:
                        stats['open_ports'] = df['open_ports'].astype(float).sum()
                    except Exception:
                        stats['open_ports'] = 0
                else:
                    stats['open_ports'] = 0
                recent_devices = csv_data[:10]
            except Exception as e:
                print(f"CSV parse error: {e}")
        # --- End dynamic CSV stats logic ---
        if request.method == 'POST':
            if 'analyze_protection' in request.form:
                uploaded_file = get_latest_upload()
                if uploaded_file:
                    try:
                        protection_analysis = data_analyzer.analyze_protection(uploaded_file)
                        device_mapping = data_analyzer.map_devices_by_category(uploaded_file)
                        flash('🛡️ Protection analysis completed successfully', 'success')
                    except Exception as e:
                        flash(f'❌ Protection analysis failed: {str(e)}', 'error')
                else:
                    flash('❌ Please upload a dataset first', 'error')
            elif 'generate_ansible' in request.form:
                system_type = request.form.get('system_type')
                config_type = request.form.get('config_type', 'security_hardening')
                try:
                    ansible_config = generate_ansible_config(system_type, config_type)
                    from flask import send_file
                    import io
                    file_obj = io.BytesIO(ansible_config.encode())
                    filename = f"ansible_{system_type}_{config_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yml"
                    return send_file(
                        file_obj,
                        as_attachment=True,
                        download_name=filename,
                        mimetype='text/yaml'
                    )
                except Exception as e:
                    flash(f'❌ Ansible config generation failed: {str(e)}', 'error')
        return render_template('protect.html', 
                             protection_analysis=protection_analysis,
                             device_mapping=device_mapping,
                             ansible_systems=ansible_systems,
                             stats=stats,
                             recent_devices=recent_devices,
                             csv_data=csv_data)
    except Exception as e:
        flash(f'❌ System error: {str(e)}', 'error')
        return render_template('protect.html', ansible_systems=get_ansible_supported_systems(), stats={'network_devices': 0, 'bluetooth_devices': 0, 'high_risk_devices': 0, 'open_ports': 0}, recent_devices=[], csv_data=None)

@app.route('/api/recovery/scan', methods=['POST'])
def recovery_scan():
    """Simulate IoT recovery scan and return JSON"""
    mechanisms = [
        {"id": 1, "name": "Multi-Factor Authentication (MFA)",
         "description": "Ensures users verify identity using multiple factors before device recovery or access.",
         "status": "pending"},
        {"id": 2, "name": "Firmware Update Validation",
         "description": "Validates firmware integrity and authenticity before installation on IoT devices.",
         "status": "pending"},
        {"id": 3, "name": "Backup & Restore",
         "description": "Allows recovery of configurations and data from secure backups after compromise.",
         "status": "pending"},
        {"id": 4, "name": "Certificate Renewal",
         "description": "Automatically renews expired or compromised digital certificates for secure communication.",
         "status": "pending"},
    ]

    devices = [
        {"id": 1, "name": "Thermostat-01", "type": "Temperature Sensor", "status": "pending"},
        {"id": 2, "name": "SmartPlug-07", "type": "Power Controller", "status": "pending"},
        {"id": 3, "name": "Cam-02", "type": "Security Camera", "status": "pending"},
        {"id": 4, "name": "DoorLock-05", "type": "Access Control", "status": "pending"},
    ]

    logs = []
    logs.append(f"[{datetime.now().isoformat()}] Recovery scan started...")

    for m in mechanisms:
        if np.random.rand() > 0.4:
            m["status"] = "completed"
            logs.append(f"[{datetime.now().isoformat()}] {m['name']} recovered successfully.")
        else:
            m["status"] = "in-progress"
            logs.append(f"[{datetime.now().isoformat()}] {m['name']} still in progress.")

    for d in devices:
        d["status"] = "recovered" if np.random.rand() > 0.5 else "recovering"

    ota_progress = int(np.random.rand() * 100)
    logs.append(f"[{datetime.now().isoformat()}] OTA update progress: {ota_progress}%")

    return jsonify({
        "mechanisms": mechanisms,
        "devices": devices,
        "logs": logs,
        "ota": ota_progress
    })

def get_ansible_supported_systems():
    """Get list of systems supported for Ansible configuration generation"""
    return [
        {
            'id': 'linux_general',
            'name': 'Linux General',
            'type': 'linux',
            'description': 'General Linux security hardening for all distributions',
            'icon': '🐧',
            'config_types': ['security_hardening', 'firewall', 'audit', 'compliance']
        },
        {
            'id': 'ubuntu',
            'name': 'Ubuntu Linux',
            'type': 'linux',
            'description': 'Ubuntu-specific security hardening and configuration',
            'icon': '🎯',
            'config_types': ['security_hardening', 'firewall', 'updates', 'services']
        },
        {
            'id': 'centos',
            'name': 'CentOS/RHEL',
            'type': 'linux',
            'description': 'CentOS and Red Hat Enterprise Linux security',
            'icon': '🔴',
            'config_types': ['security_hardening', 'selinux', 'firewalld', 'compliance']
        },
        {
            'id': 'suse',
            'name': 'SUSE Linux',
            'type': 'linux',
            'description': 'SUSE Linux Enterprise and openSUSE security',
            'icon': '🦎',
            'config_types': ['security_hardening', 'apparmor', 'firewall', 'yast']
        },
        {
            'id': 'debian',
            'name': 'Debian',
            'type': 'linux',
            'description': 'Debian Linux security hardening',
            'icon': '🌀',
            'config_types': ['security_hardening', 'firewall', 'apt_security', 'services']
        },
        {
            'id': 'windows',
            'name': 'Windows Server',
            'type': 'windows',
            'description': 'Windows Server security policies and hardening',
            'icon': '🪟',
            'config_types': ['security_policy', 'firewall', 'services', 'updates']
        },
        {
            'id': 'macos',
            'name': 'macOS',
            'type': 'macos',
            'description': 'macOS security configuration and hardening',
            'icon': '🍎',
            'config_types': ['security_hardening', 'firewall', 'privacy', 'updates']
        },
        {
            'id': 'paloalto',
            'name': 'Palo Alto Firewall',
            'type': 'firewall',
            'description': 'Palo Alto Networks firewall configuration',
            'icon': '🛡️',
            'config_types': ['security_policy', 'nat_policy', 'threat_prevention', 'url_filtering']
        },
        {
            'id': 'fortinet',
            'name': 'Fortinet Firewall',
            'type': 'firewall',
            'description': 'Fortinet FortiGate firewall security configuration',
            'icon': '🏰',
            'config_types': ['security_policy', 'firewall_policy', 'vpn', 'web_filter']
        },
        {
            'id': 'vmware',
            'name': 'VMware ESXi',
            'type': 'virtualization',
            'description': 'VMware ESXi hypervisor security hardening',
            'icon': '⚡',
            'config_types': ['security_hardening', 'vsphere', 'access_control', 'network']
        },
        {
            'id': 'docker',
            'name': 'Docker Host',
            'type': 'container',
            'description': 'Docker container security and hardening',
            'icon': '🐳',
            'config_types': ['container_security', 'daemon_config', 'image_scanning', 'runtime']
        },
        {
            'id': 'kubernetes',
            'name': 'Kubernetes',
            'type': 'orchestration',
            'description': 'Kubernetes cluster security configuration',
            'icon': '☸️',
            'config_types': ['pod_security', 'network_policies', 'rbac', 'secrets']
        }
    ]

def generate_ansible_config(system_type, config_type):
    """Generate Ansible configuration for different systems and security types"""
    
    config_generators = {
        'linux_general': generate_linux_general_config,
        'ubuntu': generate_ubuntu_config,
        'centos': generate_centos_config,
        'suse': generate_suse_config,
        'debian': generate_debian_config,
        'windows': generate_windows_config,
        'macos': generate_macos_config,
        'paloalto': generate_paloalto_config,
        'fortinet': generate_fortinet_config,
        'vmware': generate_vmware_config,
        'docker': generate_docker_config,
        'kubernetes': generate_kubernetes_config
    }
    
    if system_type in config_generators:
        return config_generators[system_type](config_type)
    else:
        return generate_linux_general_config(config_type)

def generate_linux_general_config(config_type):
    """Generate general Linux security hardening Ansible playbook"""
    
    if config_type == 'security_hardening':
        return """---
# Linux General Security Hardening Playbook
# Generated by IoT NIST Monitor - {timestamp}
# Applies to: All Linux distributions (Ubuntu, CentOS, Debian, SUSE, etc.)

- name: Linux General Security Hardening
  hosts: all
  become: yes
  vars:
    min_uid: 1000
    max_sys_uid: 999
    password_min_days: 7
    password_max_days: 90
    password_warn_age: 14
  
  tasks:
    - name: Ensure package manager cache is updated
      package_facts:
        manager: auto
    
    - name: Install essential security packages
      package:
        name:
          - fail2ban
          - auditd
          - aide
          - unattended-upgrades
          - lynis
        state: present
    
    - name: Configure SSH security
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "^{{ item.key }}"
        line: "{{ item.key }} {{ item.value }}"
        state: present
        backup: yes
      with_items:
        - { key: 'PermitRootLogin', value: 'no' }
        - { key: 'PasswordAuthentication', value: 'no' }
        - { key: 'Protocol', value: '2' }
        - { key: 'X11Forwarding', value: 'no' }
        - { key: 'MaxAuthTries', value: '3' }
        - { key: 'ClientAliveInterval', value: '300' }
        - { key: 'ClientAliveCountMax', value: '2' }
      notify: restart ssh
    
    - name: Set password aging policies
      lineinfile:
        path: /etc/login.defs
        regexp: "^{{ item.key }}\\s"
        line: "{{ item.key }} {{ item.value }}"
        state: present
      with_items:
        - { key: 'PASS_MAX_DAYS', value: '90' }
        - { key: 'PASS_MIN_DAYS', value: '7' }
        - { key: 'PASS_WARN_AGE', value: '14' }
        - { key: 'UMASK', value: '027' }
    
    - name: Configure system audit rules
      copy:
        content: |
          ## First rule - delete all
          -D

          ## Increase the buffers to survive stress events.
          ## Make this bigger for busy systems
          -b 8192

          ## Set failure mode to syslog
          -f 1

          ## Monitor file deletion
          -a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
          -a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

          ## Monitor system administration actions
          -w /etc/sudoers -p wa -k actions
          -w /etc/sudoers.d/ -p wa -k actions

          ## Monitor kernel module loading and unloading
          -w /sbin/insmod -p x -k modules
          -w /sbin/rmmod -p x -k modules
          -w /sbin/modprobe -p x -k modules
        dest: /etc/audit/rules.d/50-security.rules
        owner: root
        group: root
        mode: 0640
      when: ansible_os_family != "RedHat"
    
    - name: Ensure permissions on sensitive files
      file:
        path: "{{ item.path }}"
        owner: root
        group: root
        mode: "{{ item.mode }}"
      with_items:
        - { path: '/etc/passwd', mode: '0644' }
        - { path: '/etc/shadow', mode: '0000' }
        - { path: '/etc/group', mode: '0644' }
        - { path: '/etc/gshadow', mode: '0000' }
        - { path: '/etc/passwd-', mode: '0600' }
        - { path: '/etc/shadow-', mode: '0600' }
        - { path: '/etc/group-', mode: '0600' }
        - { path: '/etc/gshadow-', mode: '0600' }
    
    - name: Disable unused filesystems
      modprobe:
        name: "{{ item }}"
        state: absent
      with_items:
        - cramfs
        - freevxfs
        - jffs2
        - hfs
        - hfsplus
        - squashfs
        - udf
        - usb-storage
    
    - name: Configure sysctl security parameters
      sysctl:
        name: "{{ item.key }}"
        value: "{{ item.value }}"
        state: present
        reload: yes
      with_items:
        - { key: 'net.ipv4.ip_forward', value: '0' }
        - { key: 'net.ipv4.conf.all.send_redirects', value: '0' }
        - { key: 'net.ipv4.conf.default.send_redirects', value: '0' }
        - { key: 'net.ipv4.conf.all.accept_redirects', value: '0' }
        - { key: 'net.ipv4.conf.default.accept_redirects', value: '0' }
        - { key: 'net.ipv4.conf.all.accept_source_route', value: '0' }
        - { key: 'net.ipv4.conf.default.accept_source_route', value: '0' }
        - { key: 'net.ipv4.conf.all.log_martians', value: '1' }
        - { key: 'net.ipv4.conf.default.log_martians', value: '1' }
        - { key: 'net.ipv4.icmp_echo_ignore_broadcasts', value: '1' }
        - { key: 'net.ipv4.icmp_ignore_bogus_error_responses', value: '1' }
        - { key: 'net.ipv4.tcp_syncookies', value: '1' }
        - { key: 'net.ipv6.conf.all.accept_redirects', value: '0' }
        - { key: 'net.ipv6.conf.default.accept_redirects', value: '0' }
    
    - name: Ensure cron is configured properly
      cron:
        name: "AIDE check"
        hour: "5"
        minute: "0"
        job: "/usr/sbin/aide --check"
        user: root
    
    - name: Configure fail2ban
      copy:
        content: |
          [DEFAULT]
          bantime = 3600
          findtime = 600
          maxretry = 3
          backend = auto

          [sshd]
          enabled = true
          port = ssh
          filter = sshd
          logpath = /var/log/auth.log
          maxretry = 3
        dest: /etc/fail2ban/jail.local
        owner: root
        group: root
        mode: 0644
    
  handlers:
    - name: restart ssh
      service:
        name: ssh
        state: restarted
        enabled: yes
""".format(timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    elif config_type == 'firewall':
        return """---
# Linux Firewall Configuration Playbook
# Generated by IoT NIST Monitor

- name: Configure Linux Firewall
  hosts: all
  become: yes
  
  tasks:
    - name: Ensure UFW is installed (Ubuntu/Debian)
      package:
        name: ufw
        state: present
      when: ansible_os_family == "Debian"
    
    - name: Configure UFW rules
      ufw:
        rule: "{{ item.rule }}"
        port: "{{ item.port }}"
        proto: "{{ item.proto | default('tcp') }}"
      with_items:
        - { rule: 'allow', port: '22', proto: 'tcp' }   # SSH
        - { rule: 'allow', port: '80', proto: 'tcp' }   # HTTP
        - { rule: 'allow', port: '443', proto: 'tcp' }  # HTTPS
        - { rule: 'deny', port: '23', proto: 'tcp' }    # Telnet
      when: ansible_os_family == "Debian"
    
    - name: Enable UFW
      ufw:
        state: enabled
      when: ansible_os_family == "Debian"
    
    - name: Ensure firewalld is installed (RHEL/CentOS)
      package:
        name: firewalld
        state: present
      when: ansible_os_family == "RedHat"
    
    - name: Configure firewalld
      firewalld:
        service: "{{ item }}"
        state: enabled
        permanent: yes
        immediate: yes
      with_items:
        - ssh
        - http
        - https
      when: ansible_os_family == "RedHat"
    
    - name: Start and enable firewalld
      service:
        name: firewalld
        state: started
        enabled: yes
      when: ansible_os_family == "RedHat"
"""

def generate_ubuntu_config(config_type):
    """Generate Ubuntu-specific security configuration"""
    base_config = generate_linux_general_config(config_type)
    ubuntu_specific = """
    - name: Enable Ubuntu security repositories
      apt_repository:
        repo: "ppa:ubuntu-security/ppa"
        state: present
        update_cache: yes
    
    - name: Configure Ubuntu automatic security updates
      copy:
        content: |
          APT::Periodic::Update-Package-Lists "1";
          APT::Periodic::Download-Upgradeable-Packages "1";
          APT::Periodic::AutocleanInterval "7";
          APT::Periodic::Unattended-Upgrade "1";
        dest: /etc/apt/apt.conf.d/20auto-upgrades
        owner: root
        group: root
        mode: 0644
    
    - name: Install Ubuntu security tools
      package:
        name:
          - ubuntu-advantage-tools
          - usbguard
          - apparmor-profiles
        state: present
"""
    return base_config + ubuntu_specific

def generate_centos_config(config_type):
    """Generate CentOS/RHEL-specific security configuration"""
    if config_type == 'security_hardening':
        return """---
# CentOS/RHEL Security Hardening Playbook
# Generated by IoT NIST Monitor - {timestamp}

- name: CentOS/RHEL Security Hardening
  hosts: all
  become: yes
  
  tasks:
    - name: Install EPEL repository
      package:
        name: epel-release
        state: present
    
    - name: Install security packages
      package:
        name:
          - fail2ban
          - aide
          - lynis
          - rkhunter
        state: present
    
    - name: Configure SELinux
      selinux:
        state: enforcing
        policy: targeted
    
    - name: Configure firewalld
      firewalld:
        service: "{{ item }}"
        state: enabled
        permanent: yes
        immediate: yes
      with_items:
        - ssh
        - http
        - https
    
    - name: Enable and start firewalld
      service:
        name: firewalld
        state: started
        enabled: yes
    
    - name: Set password policies
      lineinfile:
        path: /etc/login.defs
        regexp: "^{{ item.key }}\\s"
        line: "{{ item.key }} {{ item.value }}"
        state: present
      with_items:
        - { key: 'PASS_MAX_DAYS', value: '90' }
        - { key: 'PASS_MIN_DAYS', value: '7' }
        - { key: 'PASS_WARN_AGE', value: '14' }
    
    - name: Configure SSH security
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "^{{ item.key }}"
        line: "{{ item.key }} {{ item.value }}"
        state: present
        backup: yes
      with_items:
        - { key: 'PermitRootLogin', value: 'no' }
        - { key: 'Protocol', value: '2' }
        - { key: 'X11Forwarding', value: 'no' }
      notify: restart sshd
    
  handlers:
    - name: restart sshd
      service:
        name: sshd
        state: restarted
""".format(timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

def generate_windows_config(config_type):
    """Generate Windows Server security configuration"""
    if config_type == 'security_policy':
        return """---
# Windows Server Security Policy Playbook
# Generated by IoT NIST Monitor - {timestamp}

- name: Windows Server Security Hardening
  hosts: windows
  gather_facts: false
  
  tasks:
    - name: Configure Windows Firewall
      win_firewall:
        profile: domain
        state: enabled
    
    - name: Enable Windows Defender
      win_defender:
        enabled: true
    
    - name: Set password policy
      win_user_right:
        name: SeNetworkLogonRight
        users: []
        action: set
    
    - name: Disable SMBv1
      win_feature:
        name: FS-SMB1
        state: absent
    
    - name: Configure audit policies
      win_audit_policy_system:
        category: "Account Logon"
        subcategory: "Credential Validation"
        audit_type: success
    
    - name: Set UAC level
      win_regedit:
        path: HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System
        name: ConsentPromptBehaviorAdmin
        data: 2
        type: dword
""".format(timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

def generate_docker_config(config_type):
    """Generate Docker security configuration"""
    if config_type == 'container_security':
        return """---
# Docker Container Security Playbook
# Generated by IoT NIST Monitor - {timestamp}

- name: Docker Security Hardening
  hosts: docker_hosts
  become: yes
  
  tasks:
    - name: Ensure Docker is installed
      package:
        name: docker-ce
        state: present
    
    - name: Configure Docker daemon security
      copy:
        content: |
          {{
            "userns-remap": "default",
            "log-driver": "json-file",
            "log-opts": {{
              "max-size": "10m",
              "max-file": "3"
            }},
            "default-ulimits": {{
              "nofile": {{
                "Name": "nofile",
                "Hard": 65536,
                "Soft": 65536
              }}
            }},
            "no-new-privileges": true
          }}
        dest: /etc/docker/daemon.json
        owner: root
        group: root
        mode: 0644
      notify: restart docker
    
    - name: Configure Docker socket permissions
      file:
        path: /var/run/docker.sock
        owner: root
        group: docker
        mode: 0660
    
    - name: Install Docker security tools
      package:
        name:
          - docker-bench-security
          - trivy
        state: present
    
  handlers:
    - name: restart docker
      service:
        name: docker
        state: restarted
""".format(timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

# Stub functions for other systems (to be implemented)
def generate_suse_config(config_type):
    return """---
# SUSE Linux Security Configuration
# Stub implementation - add SUSE-specific security rules
"""

def generate_debian_config(config_type):
    return """---
# Debian Security Configuration  
# Stub implementation - add Debian-specific security rules
"""

def generate_macos_config(config_type):
    return """---
# macOS Security Configuration
# Stub implementation - add macOS-specific security rules
"""

def generate_paloalto_config(config_type):
    return """---
# Palo Alto Firewall Configuration
# Stub implementation - add Palo Alto-specific security rules
"""

def generate_fortinet_config(config_type):
    return """---
# Fortinet Firewall Configuration
# Stub implementation - add Fortinet-specific security rules
"""

def generate_vmware_config(config_type):
    return """---
# VMware ESXi Security Configuration
# Stub implementation - add VMware-specific security rules
"""

def generate_kubernetes_config(config_type):
    return """---
# Kubernetes Security Configuration
# Stub implementation - add Kubernetes-specific security rules
"""

@app.route('/download_ansible/<system_type>/<config_type>')
def download_ansible_config(system_type, config_type):
    """Direct download endpoint for Ansible configurations"""
    try:
        ansible_config = generate_ansible_config(system_type, config_type)
        
        from flask import send_file
        import io
        
        file_obj = io.BytesIO(ansible_config.encode())
        filename = f"ansible_{system_type}_{config_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yml"
        
        return send_file(
            file_obj,
            as_attachment=True,
            download_name=filename,
            mimetype='text/yaml'
        )
        
    except Exception as e:
        flash(f'❌ Ansible config download failed: {str(e)}', 'error')
        return redirect(url_for('protect'))

@app.route('/favicon.ico')
def favicon():
    return '', 204  # Return empty response with 204 status (No Content)

@app.route('/detect', methods=['GET', 'POST'])
def detect():
    """NIST Phase 3: Detect - Vulnerability Scanning & Anomaly Detection"""
    try:
        detection_results = None
        cve_results = None
        dorking_results = None
        
        if request.method == 'POST':
            if 'scan_vulnerabilities' in request.form:
                device_type = request.form.get('device_type', '')
                vendor = request.form.get('vendor', '')
                
                try:
                    cve_results = vuln_scanner.search_cves(device_type, vendor)
                    flash(f'🔍 Found {len(cve_results)} potential vulnerabilities for {vendor} {device_type}', 'success')
                except Exception as e:
                    flash(f'❌ Vulnerability scan failed: {str(e)}', 'error')
            
            elif 'detect_anomalies' in request.form:
                uploaded_file = get_latest_upload()
                if uploaded_file:
                    try:
                        detection_results = data_analyzer.detect_anomalies(uploaded_file)
                        if 'error' in detection_results:
                            flash(f'❌ Anomaly detection failed: {detection_results["error"]}', 'error')
                        else:
                            flash(f'⚠️ Found {detection_results["total_anomalies"]} anomalous devices', 'success')
                    except Exception as e:
                        flash(f'❌ Anomaly detection failed: {str(e)}', 'error')
                else:
                    flash('❌ Please upload a dataset first', 'error')
            
            elif 'google_dorking' in request.form:
                search_terms = request.form.get('dork_terms', '')
                device_type = request.form.get('device_type', '')
                
                try:
                    dorking_results = vuln_scanner.google_dorking(search_terms, device_type)
                    flash(f'🌐 Generated {len(dorking_results)} Google dorking queries', 'success')
                except Exception as e:
                    flash(f'❌ Google dorking failed: {str(e)}', 'error')
        
        return render_template('detect.html',
                             detection_results=detection_results,
                             cve_results=cve_results,
                             dorking_results=dorking_results)
                             
    except Exception as e:
        flash(f'❌ System error: {str(e)}', 'error')
        return render_template('detect.html')

# NEW: Enhanced Respond Route with Incident Management
@app.route('/respond', methods=['GET', 'POST'])
def respond():
    """NIST Phase 4: Respond - Incident Management & Response Actions"""
    try:
        incidents = []
        alerts = []
        response_actions = None
        
        # Get incidents from database if available
        if INCIDENT_RESPONSE_AVAILABLE:
            try:
                incidents = Incident.query.order_by(Incident.detected_at.desc()).all()
                incidents = [incident.to_dict() for incident in incidents]
            except Exception as e:
                print(f"Error loading incidents: {e}")
                incidents = []
        
        if request.method == 'POST':
            if 'generate_alerts' in request.form:
                uploaded_file = get_latest_upload()
                if uploaded_file:
                    try:
                        alerts = data_analyzer.generate_alerts(uploaded_file)
                        response_actions = data_analyzer.suggest_response_actions(alerts)
                        flash(f'🚨 Generated {len(alerts)} security alerts', 'success')
                    except Exception as e:
                        flash(f'❌ Alert generation failed: {str(e)}', 'error')
                else:
                    flash('❌ Please upload a dataset first', 'error')
            
            # Create new incident
            elif 'create_incident' in request.form:
                try:
                    incident_data = {
                        'title': request.form.get('incident_title', '').strip(),
                        'description': request.form.get('incident_description', '').strip(),
                        'severity': request.form.get('incident_severity', 'medium'),
                        'device_id': request.form.get('device_id'),
                        'incident_type': request.form.get('incident_type', '')
                    }
                    
                    if not incident_data['title']:
                        flash('❌ Incident title is required', 'error')
                    else:
                        incident = incident_response_service.create_incident(**incident_data)
                        flash(f'✅ Incident "{incident_data["title"]}" created successfully', 'success')
                        return redirect(url_for('respond'))
                        
                except Exception as e:
                    flash(f'❌ Failed to create incident: {str(e)}', 'error')
        
        return render_template('respond.html',
                             incidents=incidents,
                             alerts=alerts,
                             response_actions=response_actions,
                             incident_response_available=INCIDENT_RESPONSE_AVAILABLE)
                             
    except Exception as e:
        flash(f'❌ System error: {str(e)}', 'error')
        return render_template('respond.html',
                             incidents=[],
                             alerts=[],
                             response_actions=None,
                             incident_response_available=INCIDENT_RESPONSE_AVAILABLE)

# NEW: Incident Management API Routes
@app.route('/api/incidents', methods=['GET', 'POST'])
def api_incidents():
    """API endpoint for incident management"""
    try:
        if request.method == 'POST':
            data = request.json
            if not data:
                return jsonify({'success': False, 'error': 'No JSON data provided'})
            
            incident = incident_response_service.create_incident(
                title=data.get('title'),
                description=data.get('description'),
                severity=data.get('severity', 'medium'),
                device_id=data.get('device_id'),
                incident_type=data.get('incident_type')
            )
            
            return jsonify({'success': True, 'incident': incident.to_dict()})
        
        else:  # GET request
            if INCIDENT_RESPONSE_AVAILABLE:
                incidents = Incident.query.order_by(Incident.detected_at.desc()).all()
                return jsonify([incident.to_dict() for incident in incidents])
            else:
                return jsonify([])
                
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/incidents/<int:incident_id>', methods=['GET', 'PUT', 'DELETE'])
def api_incident_detail(incident_id):
    """API endpoint for individual incident operations"""
    try:
        if not INCIDENT_RESPONSE_AVAILABLE:
            return jsonify({'success': False, 'error': 'Incident response not available'})
        
        incident = Incident.query.get(incident_id)
        if not incident:
            return jsonify({'success': False, 'error': 'Incident not found'})
        
        if request.method == 'GET':
            return jsonify({'success': True, 'incident': incident.to_dict()})
        
        elif request.method == 'PUT':
            data = request.json
            if 'status' in data:
                incident.status = data['status']
                if data['status'] == 'contained':
                    incident.contained_at = datetime.utcnow()
                elif data['status'] == 'resolved':
                    incident.resolved_at = datetime.utcnow()
            
            from IOT import db
            db.session.commit()
            return jsonify({'success': True, 'incident': incident.to_dict()})
        
        elif request.method == 'DELETE':
            from IOT import db
            db.session.delete(incident)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Incident deleted'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/incidents/<int:incident_id>/actions', methods=['POST'])
def api_incident_actions(incident_id):
    """API endpoint for incident response actions"""
    try:
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'No JSON data provided'})
        
        result = incident_response_service.take_manual_action(
            incident_id=incident_id,
            action_type=data.get('action_type'),
            parameters=data.get('parameters', {})
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/incidents/actions', methods=['POST'])
def api_manual_actions():
    """API endpoint for manual response actions (without specific incident)"""
    try:
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'No JSON data provided'})
        
        # Create a temporary incident for the action
        incident = incident_response_service.create_incident(
            title=f"Manual Action: {data.get('action_type', 'unknown')}",
            description="Automatically created for manual response action",
            severity="medium"
        )
        
        result = incident_response_service.take_manual_action(
            incident_id=incident.id,
            action_type=data.get('action_type'),
            parameters=data.get('parameters', {})
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/playbooks', methods=['GET', 'POST'])
def api_playbooks():
    """API endpoint for response playbooks"""
    try:
        if not INCIDENT_RESPONSE_AVAILABLE:
            return jsonify({'success': False, 'error': 'Incident response not available'})
        
        if request.method == 'POST':
            data = request.json
            playbook = ResponsePlaybook(
                name=data.get('name'),
                description=data.get('description'),
                trigger_conditions=json.dumps(data.get('trigger_conditions', {})),
                actions=json.dumps(data.get('actions', [])),
                is_active=data.get('is_active', True)
            )
            
            from IOT import db
            db.session.add(playbook)
            db.session.commit()
            
            return jsonify({'success': True, 'playbook': playbook.to_dict()})
        
        else:  # GET request
            playbooks = ResponsePlaybook.query.all()
            return jsonify([playbook.to_dict() for playbook in playbooks])
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/recover', methods=['GET', 'POST'])
def recover():
    """NIST Phase 5: Recover - Recovery Planning & Backup Status"""
    try:
        recovery_plan = None
        backup_status = None
        
        if request.method == 'POST' and 'generate_recovery_plan' in request.form:
            uploaded_file = get_latest_upload()
            if uploaded_file:
                try:
                    recovery_plan = data_analyzer.generate_recovery_plan(uploaded_file)
                    backup_status = data_analyzer.check_backup_status(uploaded_file)
                    flash('🔄 Recovery plan generated successfully', 'success')
                except Exception as e:
                    flash(f'❌ Recovery plan generation failed: {str(e)}', 'error')
            else:
                flash('❌ Please upload a dataset first', 'error')
        
        return render_template('recover.html',
                             recovery_plan=recovery_plan,
                             backup_status=backup_status)
                             
    except Exception as e:
        flash(f'❌ System error: {str(e)}', 'error')
        return render_template('recover.html')

@app.route('/devicehive', methods=['GET', 'POST'])
def devicehive():
    """DeviceHive Integration - Real-time Monitoring"""
    try:
        devices = []
        real_time_data = None
        
        if request.method == 'POST':
            if 'connect_devicehive' in request.form:
                server_url = request.form.get('server_url', '')
                access_token = request.form.get('access_token', '')
                
                if server_url and access_token:
                    try:
                        if devicehive_client.connect(server_url, access_token):
                            devices = devicehive_client.get_devices()
                            flash('✅ Successfully connected to DeviceHive', 'success')
                        else:
                            flash('❌ Failed to connect to DeviceHive', 'error')
                    except Exception as e:
                        flash(f'❌ DeviceHive connection failed: {str(e)}', 'error')
                else:
                    flash('❌ Please provide both server URL and access token', 'error')
            
            elif 'start_monitoring' in request.form:
                device_id = request.form.get('device_id', '')
                if device_id:
                    try:
                        real_time_data = devicehive_client.start_monitoring(device_id)
                        flash(f'📊 Started monitoring device: {device_id}', 'success')
                    except Exception as e:
                        flash(f'❌ Device monitoring failed: {str(e)}', 'error')
                else:
                    flash('❌ Please select a device to monitor', 'error')
        
        return render_template('devicehive.html',
                             devices=devices,
                             real_time_data=real_time_data)
                             
    except Exception as e:
        flash(f'❌ System error: {str(e)}', 'error')
        return render_template('devicehive.html')

@app.route('/start_aws_simulation', methods=['POST'])
def start_aws_simulation():
    """Start AWS IoT simulation"""
    global aws_iot_process
    
    try:
        # Check if simulation is already running
        if aws_iot_process and aws_iot_process.poll() is None:
            return jsonify({
                'success': False, 
                'error': 'AWS IoT simulation is already running'
            })
        
        # Create the simulation script
        script_path = create_aws_iot_simulation_script()
        
        # Start the simulation in a subprocess
        if os.name == 'nt':  # Windows
            aws_iot_process = subprocess.Popen(
                ['python', script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        else:  # Unix-like systems
            aws_iot_process = subprocess.Popen(
                [script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        
        # Start a thread to monitor the process output
        def monitor_output():
            while aws_iot_process and aws_iot_process.poll() is None:
                output = aws_iot_process.stdout.readline()
                if output:
                    print(f"AWS IoT Simulation: {output.strip()}")
        
        monitor_thread = threading.Thread(target=monitor_output)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        flash('🚀 AWS IoT simulation started successfully', 'success')
        return jsonify({
            'success': True,
            'message': 'AWS IoT simulation started successfully'
        })
        
    except Exception as e:
        print(f"AWS IoT simulation error: {e}")
        return jsonify({
            'success': False,
            'error': f'Failed to start AWS IoT simulation: {str(e)}'
        })

@app.route('/stop_aws_simulation', methods=['POST'])
def stop_aws_simulation():
    """Stop AWS IoT simulation"""
    global aws_iot_process
    
    try:
        if aws_iot_process and aws_iot_process.poll() is None:
            # Terminate the process
            aws_iot_process.terminate()
            
            # Wait for process to terminate
            try:
                aws_iot_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Force kill if not terminated
                aws_iot_process.kill()
                aws_iot_process.wait()
            
            aws_iot_process = None
            flash('🛑 AWS IoT simulation stopped successfully', 'success')
            return jsonify({
                'success': True,
                'message': 'AWS IoT simulation stopped successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'No AWS IoT simulation is currently running'
            })
            
    except Exception as e:
        print(f"Error stopping AWS IoT simulation: {e}")
        return jsonify({
            'success': False,
            'error': f'Failed to stop AWS IoT simulation: {str(e)}'
        })

@app.route('/aws_simulation_status')
def aws_simulation_status():
    """Check AWS IoT simulation status"""
    global aws_iot_process
    
    if aws_iot_process and aws_iot_process.poll() is None:
        return jsonify({
            'running': True,
            'status': 'Simulation is running'
        })
    else:
        return jsonify({
            'running': False,
            'status': 'Simulation is not running'
        })

@app.route('/report')
def report():
    """Comprehensive NIST-based Report"""
    try:
        uploaded_file = get_latest_upload()
        report_data = None
        
        if uploaded_file:
            try:
                report_data = data_analyzer.generate_nist_report(uploaded_file)
                flash('📋 NIST compliance report generated successfully', 'success')
            except Exception as e:
                flash(f'❌ Report generation failed: {str(e)}', 'error')
        else:
            flash('❌ Please upload a dataset first to generate report', 'error')
        
        return render_template('report.html', report_data=report_data)
        
    except Exception as e:
        flash(f'❌ System error: {str(e)}', 'error')
        return render_template('report.html')

def get_latest_upload():
    """Get the most recently uploaded dataset file"""
    try:
        upload_dir = app.config['UPLOAD_FOLDER']
        # Prefer the synthetic CSV for demo if it exists
        synthetic_csv = None
        for f in os.listdir(upload_dir):
            if f.startswith('synthetic_iot_devices_') and f.endswith('.csv'):
                synthetic_csv = os.path.join(upload_dir, f)
                break
        if synthetic_csv and os.path.exists(synthetic_csv):
            return synthetic_csv
        # Fallback to most recent file
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
            return None
        files = os.listdir(upload_dir)
        allowed_files = [f for f in files if allowed_file(f)]
        if not allowed_files:
            return None
        latest_file = max(
            allowed_files, 
            key=lambda x: os.path.getctime(os.path.join(upload_dir, x))
        )
        return os.path.join(upload_dir, latest_file)
    except Exception as e:
        print(f"Error getting latest upload: {e}")
        return None

# Error handlers
@app.errorhandler(413)
def too_large(error):
    return jsonify({'error': 'File too large', 'message': f'Maximum file size is {format_file_size(app.config["MAX_CONTENT_LENGTH"])}'}), 413

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    os.makedirs('scripts', exist_ok=True)
    
    print("=" * 60)
    print("🚀 IoT NIST Monitor Starting...")
    print("=" * 60)
    print("📊 Available Routes:")
    print("  http://localhost:5001/          - Home page")
    print("  http://localhost:5001/identify  - Network scanning & asset discovery")
    print("  http://localhost:5001/protect   - Security controls analysis") 
    print("  http://localhost:5001/detect    - Vulnerability scanning & anomaly detection")
    print("  http://localhost:5001/respond   - Incident management & response actions")
    print("  http://localhost:5001/recover   - Recovery planning & backup status")
    print("  http://localhost:5001/devicehive - Real-time monitoring integration")
    print("  http://localhost:5001/report    - Comprehensive NIST-based report")
    print("=" * 60)
    print(f"💾 Max file upload size: {format_file_size(app.config['MAX_CONTENT_LENGTH'])}")
    print(f"📱 Bluetooth scanning: {'Available' if BLUETOOTH_AVAILABLE else 'Not available'}")
    print(f"📊 Asset Inventory: {'Available' if ASSET_INVENTORY_AVAILABLE else 'Not available'}")
    print(f"🚨 Incident Response: {'Available' if INCIDENT_RESPONSE_AVAILABLE else 'Not available'}")
    print(f"🔍 Passive Fingerprinting: {'Available' if PASSIVE_FINGERPRINTING_AVAILABLE else 'Not available'}")
    print(f"🔧 Protocol Analyzer: {'Available' if PROTOCOL_ANALYZER_AVAILABLE else 'Not available'}")
    print(f"📈 Risk Engine: {'Available' if RISK_ENGINE_AVAILABLE else 'Not available'}")
    print(f"🐛 CVE Lookup: {'Available' if CVE_LOOKUP_AVAILABLE else 'Not available'}")
    print(f"☁️  AWS IoT Simulation: Available")
    print("💡 Make sure nmap is installed on your system for network scanning")
    print("💡 AWS IoT SDK required for simulation: pip install AWSIoTPythonSDK")
    print("=" * 60)
    
    # Run the application on port 5001 to avoid socket permission issues
    app.run(debug=True, host='0.0.0.0', port=5001, threaded=True)