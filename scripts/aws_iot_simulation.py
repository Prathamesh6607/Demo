#!/usr/bin/env python3
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

# Use absolute or expanded paths. Example: r"C:\\path\\to\\cert.pem.crt" on Windows
ROOT_CA_PATH = os.path.expanduser(r"C:\Users\prath\OneDrive\Desktop\iot_nist_monitor\iot_nist_monitor\IOT\connect_device_package\root-CA.crt")
PRIVATE_KEY_PATH = os.path.expanduser(r"C:\Users\prath\OneDrive\Desktop\iot_nist_monitor\iot_nist_monitor\IOT\connect_device_package\demothing.private.key")
CERTIFICATE_PATH = os.path.expanduser(r"C:\Users\prath\OneDrive\Desktop\iot_nist_monitor\iot_nist_monitor\IOT\connect_device_package\demothing.cert.pem")

# Path to start.ps1 script
START_PS1_PATH = os.path.expanduser(r"C:\Users\prath\OneDrive\Desktop\iot_nist_monitor\iot_nist_monitor\start.ps1")

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
    print("\nReceived termination signal, shutting down gracefully...")
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
