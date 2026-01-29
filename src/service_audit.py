import wmi
import logging
from src.alert_engine import raise_alert

ACTIVITY_LOG = "logs/activity.log"

logging.basicConfig(
    filename=ACTIVITY_LOG,
    level=logging.INFO,
    format="%(asctime)s | %(message)s"
)

SUSPICIOUS_PATH_KEYWORDS = [
    "\\temp\\",
    "\\appdata\\",
    "\\downloads\\"
]

def audit_startup_services():
    c = wmi.WMI()
    services = c.Win32_Service()

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

        logging.info(f"SERVICE ENUMERATED | {service_data}")

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
