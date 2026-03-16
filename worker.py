import os
import json
import time
import pandas as pd
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from models import init_db, SessionLocal, AccessLog
from user_agents import parse
import logging

LOG_FILE = "/app/logs/access.log"

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class LogHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_pos = 0
        if os.path.exists(LOG_FILE):
            self.last_pos = os.path.getsize(LOG_FILE)

    def on_modified(self, event):
        if event.src_path == LOG_FILE:
            self.process_new_lines()

    def clean_ip(self, client_addr):
        if not client_addr:
            return ""
        if ':' in client_addr:
            if client_addr.startswith('['):
                return client_addr.split(']')[0].replace('[', '')
            else:
                return client_addr.rsplit(':', 1)[0]
        return client_addr

    def process_new_lines(self):
        session = SessionLocal()
        try:
            with open(LOG_FILE, 'r') as f:
                f.seek(self.last_pos)
                for line in f:
                    try:
                        data = json.loads(line)
                        
                        # Clean IP address
                        client_ip = self.clean_ip(data.get('ClientAddr', ''))
                        
                        # Parse User-Agent
                        ua_string = data.get('RequestUserAgent', '')
                        ua = parse(ua_string)
                        
                        log_entry = AccessLog(
                            start_local=pd.to_datetime(data.get('StartLocal')),
                            client_addr=client_ip,
                            
                            # Geo (Placeholder for now)
                            country_code=None,
                            city_name=None,
                            asn=None,
                            
                            # Request
                            request_method=data.get('RequestMethod'),
                            request_path=data.get('RequestPath'),
                            request_host=data.get('RequestHost'),
                            request_protocol=data.get('RequestProtocol'),
                            request_referer=data.get('RequestReferer'),
                            request_user_agent=ua_string,
                            
                            # Bot Detection
                            is_bot=ua.is_bot,
                            browser_family=ua.browser.family,
                            os_family=ua.os.family,
                            device_family=ua.device.family,
                            
                            # Traefik Data
                            entry_point=data.get('EntryPointName'),
                            status_code=int(data.get('DownstreamStatus', 0)),
                            duration=int(data.get('Duration', 0)),
                            content_size=int(data.get('DownstreamContentSize', 0))
                        )
                        session.add(log_entry)
                        session.commit()
                    except Exception as e:
                        session.rollback()
                        continue
                self.last_pos = f.tell()
        finally:
            session.close()

if __name__ == "__main__":
    init_db()
    logger.info(f"Starting worker, monitoring {LOG_FILE}...")
    
    # Initial processing of existing logs
    handler = LogHandler()
    handler.last_pos = 0 
    handler.process_new_lines()
    
    observer = Observer()
    observer.schedule(handler, path=os.path.dirname(LOG_FILE), recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
