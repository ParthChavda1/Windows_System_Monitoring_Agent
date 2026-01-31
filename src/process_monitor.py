import psutil
import logging
from datetime import datetime

ACTIVITY_LOG = "logs/activity.log"

def get_activity_logger():
    logger = logging.getLogger("activity_logger")
    logger.setLevel(level=logging.INFO)

    if not logger.handlers:
        handler = logging.FileHandler(ACTIVITY_LOG)
        formatter = logging.Formatter("%(asctime)s | %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger


def enumerate_process():
    processes = []
    logger = get_activity_logger()
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
            logger.info(f"PROCESS ENUMERATED | {process_data}")
        
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        
    return processes
    