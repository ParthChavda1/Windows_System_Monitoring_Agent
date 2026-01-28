import psutil
import logging
from datetime import datetime

LOG_FILE = "logs/activity.log"

logging.basicConfig(filename= LOG_FILE,level=logging.INFO,format="%(asctime)s | %(message)s ")

def enumerate_process():
    processes = []
    
    for p in psutil.process_iter(["pid","ppid","name","exe"]):
        try:
            info = p.info

            process_data = {
                "pid":info.get("pid"),
                "ppid":info.get("ppid"),
                "name":info.get("name"),
                "path":info.get("exe"),
            }
            processes.append(process_data)
            logging.info(f"PROCESS ENUMERATED | {process_data}")
        
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        
    return processes
    