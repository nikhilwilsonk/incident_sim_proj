import time
import json
import datetime
import logging
from jinja2 import Template
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from utils import ATTACK_MAPPING,MITIGATIONS
import os
os.makedirs('/var/log/response', exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/response/responder.log'),
        logging.StreamHandler()
    ]
)

class IncidentResponder(FileSystemEventHandler):
    def __init__(self):
        self.alert_queue = []
        self.processed_incidents = set()

        with open('/app/report_template.html', 'r') as f:
            self.report_template = Template(f.read()) #report template build
    
    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith('alerts.json'):
            self.process_alerts(event.src_path)
    
    def process_alerts(self, alert_file):
        with open(alert_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    alert = json.loads(line)
                    # Check if we've already processed this incident
                    if alert['incident_id'] not in self.processed_incidents:
                        self.handle_incident(alert)
                        self.processed_incidents.add(alert['incident_id'])
                except json.JSONDecodeError:
                    logging.error(f"Failed to parse alert JSON: {line}")
                except Exception as e:
                    logging.error(f"Error processing alert: {str(e)}")
    
    def handle_incident(self, alert):
        logging.info(f"Handling incident {alert['incident_id']} - {alert['threat_type']}")
        
        attack_info = ATTACK_MAPPING.get(
            alert['threat_type'], 
            {'tactic': 'Unknown', 'technique': 'Unknown', 'description': 'Unknown attack vector'}
        )
        
        mitigations = MITIGATIONS.get(
            alert['threat_type'],
            ['Implement proper input validation', 'Follow secure coding practices']
        )
        
        incident = {
            **alert,
            **attack_info,
            'mitigations': mitigations,
            'response_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'status': 'detected'
        }
        logging.info(f"Incident details: {json.dumps(incident)}")
        self.generate_report(incident)
        self.take_response_actions(incident)
    
    def generate_report(self, incident):
        report_html = self.report_template.render(incident=incident)
        
        report_file = f"/var/reports/incident-{incident['incident_id']}.html"
        with open(report_file, 'w') as f:
            f.write(report_html)
        
        json_file = f"/var/reports/incident-{incident['incident_id']}.json"
        with open(json_file, 'w') as f:
            json.dump(incident, f, indent=2)
        logging.info(f"Generated incident report: {report_file}")
        
    def take_response_actions(self, incident):
        logging.info(f"Taking response actions for incident {incident['incident_id']}")
        
        incident['status'] = 'responding'
        
        if incident['severity'] == 'HIGH':
            logging.warning(f"HIGH severity incident")
            '''
            responding to the high severity incident
            after which incident status get updated
            '''
        incident['status'] = 'responded'
        incident['resolution_time'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        json_file = f"/var/reports/incident-{incident['incident_id']}.json"
        with open(json_file, 'w') as f:
            json.dump(incident, f, indent=2)

if __name__ == "__main__":
    paths_to_watch = ['/var/log/monitoring']
    
    logging.info("Starting Incident Responser")
    logging.info(f"Watching directories: {', '.join(paths_to_watch)}")
    event_handler = IncidentResponder()
    observer = Observer()
    for path in paths_to_watch:
        observer.schedule(event_handler, path, recursive=True)
    
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    
    observer.join()