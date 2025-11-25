# models/incident_models.py
from datetime import datetime
from IOT import db  # Assuming you're using SQLAlchemy

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    status = db.Column(db.String(20), default='open')  # open, in_progress, contained, resolved, closed
    incident_type = db.Column(db.String(50))  # malware, unauthorized_access, data_breach, etc.
    
    # Affected device
    device_id = db.Column(db.Integer, db.ForeignKey('iot_device.id'))
    
    # Timestamps
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    contained_at = db.Column(db.DateTime)
    resolved_at = db.Column(db.DateTime)
    
    # Response actions
    automatic_actions_taken = db.Column(db.Text)  # JSON string of automated responses
    manual_actions_taken = db.Column(db.Text)     # JSON string of manual responses
    
    # Forensic data
    forensic_data = db.Column(db.Text)  # JSON snapshot of device state
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'status': self.status,
            'incident_type': self.incident_type,
            'device_id': self.device_id,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None,
            'contained_at': self.contained_at.isoformat() if self.contained_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
        }

class ResponsePlaybook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    trigger_conditions = db.Column(db.Text)  # JSON conditions that trigger this playbook
    actions = db.Column(db.Text)  # JSON list of actions to execute
    is_active = db.Column(db.Boolean, default=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'trigger_conditions': self.trigger_conditions,
            'actions': self.actions,
            'is_active': self.is_active
        }