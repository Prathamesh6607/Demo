import os
import asyncio
import json
from flask import Flask, render_template, jsonify
from utils.iot import aws_iot_manager, nist_analyzer

app = Flask(__name__)

class NISTMonitorApp:
    def __init__(self):
        self.monitoring_devices = []
        self.compliance_reports = {}
    
    async def initialize_aws_iot(self):
        """Initialize AWS IoT connection"""
        success = await aws_iot_manager.connect(
            endpoint=os.getenv('AWS_IOT_ENDPOINT', 'a3vlu21e6pc561-ats.iot.ap-south-1.amazonaws.com'),
            cert_path=os.getenv('AWS_CERT_PATH', 'C:\Users\prath\OneDrive\Desktop\iot_nist_monitor\iot_nist_monitor\IOT\connect_device_package\root-CA.crt'),
            key_path=os.getenv('AWS_KEY_PATH', 'C:\Users\prath\OneDrive\Desktop\iot_nist_monitor\iot_nist_monitor\IOT\connect_device_package\demothing.private.key'),
            root_ca_path=os.getenv('AWS_ROOT_CA_PATH', 'C:\Users\prath\OneDrive\Desktop\iot_nist_monitor\iot_nist_monitor\IOT\connect_device_package\demothing.cert.pem'),
            client_id=os.getenv('AWS_CLIENT_ID', 'iotconsole-37f61f05-feb3-4d61-96e9-f114654b09e8')
        )
        return success
    
    def start_nist_monitoring(self, device_id):
        """Start NIST compliance monitoring for a device"""
        def monitoring_callback(device_data):
            # Analyze compliance
            analysis = nist_analyzer.analyze_compliance(device_data)
            
            # Store latest report
            self.compliance_reports[device_id] = analysis
            
            # Print to console (replace with your logging)
            print(f"🔍 NIST Analysis for {device_id}:")
            print(f"   Compliance: {analysis['overall_compliance']}")
            print(f"   Score: {analysis['compliance_score']}%")
            print(f"   Risk: {analysis['risk_assessment']}")
            
            # Update device shadow with current state
            asyncio.run_coroutine_threadsafe(
                aws_iot_manager.update_device_shadow(device_id, {
                    "compliance": analysis['overall_compliance'],
                    "compliance_score": analysis['compliance_score'],
                    "risk_level": analysis['risk_assessment'],
                    "last_updated": device_data['timestamp']
                }),
                asyncio.get_event_loop()
            )
        
        result = aws_iot_manager.start_nist_monitoring(device_id, monitoring_callback)
        if device_id not in self.monitoring_devices:
            self.monitoring_devices.append(device_id)
        
        return result
    
    def stop_nist_monitoring(self, device_id):
        """Stop monitoring a specific device"""
        aws_iot_manager.stop_monitoring_all()
        if device_id in self.monitoring_devices:
            self.monitoring_devices.remove(device_id)
    
    def get_compliance_report(self, device_id):
        """Get latest compliance report for a device"""
        return self.compliance_reports.get(device_id, {})
    
    def get_all_monitoring_devices(self):
        """Get list of all monitored devices"""
        return self.monitoring_devices


# Initialize the application
nist_app = NISTMonitorApp()

# Flask Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start-monitoring/<device_id>')
def start_monitoring(device_id):
    nist_app.start_nist_monitoring(device_id)
    return jsonify({"status": "success", "message": f"Started monitoring {device_id}"})

@app.route('/stop-monitoring/<device_id>')
def stop_monitoring(device_id):
    nist_app.stop_nist_monitoring(device_id)
    return jsonify({"status": "success", "message": f"Stopped monitoring {device_id}"})

@app.route('/compliance-report/<device_id>')
def get_compliance_report(device_id):
    report = nist_app.get_compliance_report(device_id)
    return jsonify(report)

@app.route('/monitoring-status')
def monitoring_status():
    return jsonify({
        "monitoring_devices": nist_app.get_all_monitoring_devices(),
        "aws_iot_connected": aws_iot_manager.connected
    })

# Initialize AWS IoT on startup
@app.before_first_request
def initialize_app():
    async def setup():
        await nist_app.initialize_aws_iot()
        # Start monitoring default device
        nist_app.start_nist_monitoring("nist-default-device")
    
    # Run async setup
    asyncio.run(setup())

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)