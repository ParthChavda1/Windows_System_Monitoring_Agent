import logging

ALERT_LOG = "logs/alerts.log"

# logging.basicConfig(filename=ALERT_LOG,level=logging.WARNING,format="%(asctime)s | %(message)s")
def get_alert_logger():
    logger = logging.getLogger("alert_logger")
    logger.setLevel(logging.WARNING)

    if not logger.handlers:
        handler = logging.FileHandler(ALERT_LOG)
        formatter = logging.Formatter("%(asctime)s | %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger


def raise_alert(alert_type,severity,details):
    alert = {
        "type":alert_type,
        "severity":severity,
        "details":details
    }
    logger1 = get_alert_logger()
    logger1.warning(f"ALERT | {alert}")
    # logging.warning(f"ALERT | {alert}")
    