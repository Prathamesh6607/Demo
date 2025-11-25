# utils/incident_response.py
import json
import requests
from datetime import datetime
from models.incident_models import Incident, ResponsePlaybook

class IncidentResponseService:
    def __init__(self, db):
        self.db = db
    
    def create_incident(self, title, description, severity, device_id=None, incident_type=None):
        """Create a new incident"""
        incident = Incident(
            title=title,
            description=description,
            severity=severity,
            device_id=device_id,
            incident_type=incident_type,
            status='open'
        )
        
        self.db.session.add(incident)
        self.db.session.commit()
        
        # Check if any playbooks should be triggered
        self._execute_playbooks(incident)
        
        return incident
    
    def _execute_playbooks(self, incident):
        """Execute automated playbooks based on incident"""
        playbooks = ResponsePlaybook.query.filter_by(is_active=True).all()
        
        executed_actions = []
        
        for playbook in playbooks:
            if self._should_trigger_playbook(playbook, incident):
                actions = json.loads(playbook.actions)
                for action in actions:
                    result = self._execute_action(action, incident)
                    executed_actions.append({
                        'playbook': playbook.name,
                        'action': action,
                        'result': result
                    })
        
        # Update incident with automated actions taken
        if executed_actions:
            incident.automatic_actions_taken = json.dumps(executed_actions)
            self.db.session.commit()
    
    def _should_trigger_playbook(self, playbook, incident):
        """Determine if a playbook should be triggered"""
        try:
            conditions = json.loads(playbook.trigger_conditions)
            
            # Check severity condition
            if 'severity' in conditions and incident.severity not in conditions['severity']:
                return False
            
            # Check type condition
            if 'incident_type' in conditions and incident.incident_type not in conditions['incident_type']:
                return False
            
            return True
            
        except Exception as e:
            print(f"Error checking playbook conditions: {e}")
            return False
    
    def _execute_action(self, action, incident):
        """Execute a single response action"""
        action_type = action.get('type')
        
        try:
            if action_type == 'quarantine_device' and incident.device_id:
                return self._quarantine_device(incident.device_id)
            
            elif action_type == 'block_ip':
                return self._block_ip(action.get('ip_address'))
            
            elif action_type == 'send_alert':
                return self._send_alert(action.get('channel'), incident)
            
            elif action_type == 'create_ticket':
                return self._create_ticket(incident, action.get('system'))
            
            else:
                return {'status': 'skipped', 'reason': 'unknown_action_type'}
                
        except Exception as e:
            return {'status': 'error', 'reason': str(e)}
    
    def _quarantine_device(self, device_id):
        """Quarantine a device by blocking it at network level"""
        # This would integrate with your network infrastructure
        # For now, we'll just log the action
        print(f"Quarantining device {device_id}")
        return {'status': 'success', 'action': 'device_quarantine'}
    
    def _block_ip(self, ip_address):
        """Block an IP address at firewall"""
        print(f"Blocking IP {ip_address}")
        return {'status': 'success', 'action': 'ip_block'}
    
    def _send_alert(self, channel, incident):
        """Send alert to various channels"""
        message = f"Incident Alert: {incident.title} - Severity: {incident.severity}"
        print(f"Sending alert to {channel}: {message}")
        return {'status': 'success', 'action': 'alert_sent'}
    
    def _create_ticket(self, incident, system):
        """Create ticket in external system"""
        print(f"Creating ticket in {system} for incident {incident.id}")
        return {'status': 'success', 'action': 'ticket_created'}
    
    def take_manual_action(self, incident_id, action_type, parameters):
        """Execute a manual response action"""
        incident = Incident.query.get(incident_id)
        if not incident:
            return {'error': 'Incident not found'}
        
        action_result = self._execute_action({
            'type': action_type,
            **parameters
        }, incident)
        
        # Update manual actions taken
        current_actions = json.loads(incident.manual_actions_taken or '[]')
        current_actions.append({
            'timestamp': datetime.utcnow().isoformat(),
            'action_type': action_type,
            'parameters': parameters,
            'result': action_result
        })
        incident.manual_actions_taken = json.dumps(current_actions)
        self.db.session.commit()
        
        return action_result