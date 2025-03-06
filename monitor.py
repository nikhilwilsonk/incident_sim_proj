import time
import json
import datetime
import logging
import os
import re
from utils import THREAT_PATTERNS
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

os.makedirs('log/monitoring', exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('log/monitoring/monitor.log'),
        logging.StreamHandler()
    ]
)

class SecurityMonitor(FileSystemEventHandler):
    def __init__(self):
        self.alert_count = {threat_type: 0 for threat_type in THREAT_PATTERNS}
        self.last_position = {}
    '''
    the on_modified is inherited from FileSystemEventHandler
    this is triggered when a file change happens
    here we call the check_log_file function
    which checks if the file was being tracked before,
    if not assign its last position line to 0
    '''
    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith('.log'):
            self.check_log_file(event.src_path)
    
    def check_log_file(self, file_path):
        file_name = os.path.basename(file_path)
        if file_path not in self.last_position:
            self.last_position[file_path] = 0
            
        with open(file_path, 'r') as f:
            f.seek(self.last_position[file_path]) #bring the cursor to the last pos
            new_lines = f.readlines()
            self.last_position[file_path] = f.tell()#cursors last pos after read            
        if not new_lines:
            return
        
        for line in new_lines:
            self.analyze_log_line(line, file_name)
    
    def analyze_log_line(self, line, source_file):
        for threat_type, patterns in THREAT_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.report_threat(threat_type, line, source_file)
                    self.alert_count[threat_type] += 1
                    break
    
    def report_threat(self, threat_type, log_line, source_file):
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        incident_id = f"{threat_type}-{int(time.time())}"
        
        logging.warning(f"SECURITY ALERT - Detected potential {threat_type} attack")
        logging.info(f"Incident ID: {incident_id}")
        logging.info(f"Source: {source_file}")
        logging.info(f"Raw log: {log_line.strip()}")
        alert = {
            "incident_id": incident_id,
            "timestamp": timestamp,
            "threat_type": threat_type,
            "source_file": source_file,
            "raw_log": log_line.strip(),
            "severity": self.determine_severity(threat_type)
        }
        with open('log/monitoring/alerts.json', 'a') as f:
            f.write(json.dumps(alert) + '\n')
    
    def determine_severity(self, threat_type):
        if self.alert_count[threat_type] > 5:
            return "HIGH"
        elif self.alert_count[threat_type] > 2:
            return "MEDIUM"
        else:
            return "LOW"

if __name__ == "__main__":
    paths_to_watch = ['log/webapp']
    
    logging.info("Starting Security Monitoring Service")
    logging.info(f"Watching directories: {', '.join(paths_to_watch)}")
    
    event_handler = SecurityMonitor()
    observer = Observer()
    for path in paths_to_watch:
        observer.schedule(event_handler, path, recursive=True)
    
    observer.start()
    '''
    infinite loop to keep the process on
    '''
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    
    observer.join()