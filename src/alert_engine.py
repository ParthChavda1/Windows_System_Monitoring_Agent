import logging

ALERT_LOG = "logs/alerts.log"

logging.basicConfig(filename=ALERT_LOG,level=logging.WARNING,format="%(asctime)s | %(message)s")

def raise_alert(alert_type,severity,details):
    alert = {
        "type":alert_type,
        "severity":severity,
        "details":details
    }
    logging.warning(f"ALERT | {alert}")
    
    