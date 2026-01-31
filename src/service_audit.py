import wmi
from src.alert_engine import raise_alert
from src.process_monitor import get_activity_logger

SUSPICIOUS_PATH_KEYWORDS = [
    "\\temp\\",
    "\\appdata\\",
    "\\downloads\\"
]

def audit_startup_services():
    c = wmi.WMI()
    services = c.Win32_Service()
    logger = get_activity_logger()
    for svc in services:
        name = svc.Name
        display_name = svc.DisplayName
        path = svc.PathName or ""
        start_mode = svc.StartMode

        service_data = {
            "name": name,
            "display_name": display_name,
            "path": path,
            "start_mode": start_mode
        }

        logger.info(f"SERVICE ENUMERATED | {service_data}")

        path_lower = path.lower()
        for keyword in SUSPICIOUS_PATH_KEYWORDS:
            if keyword in path_lower:
                details = (
                    f"Suspicious startup service detected: "
                    f"{name} ({display_name}) | Path: {path}"
                )

                raise_alert(
                    alert_type="Suspicious Startup Service",
                    severity="HIGH",
                    details=details
                )
                break
