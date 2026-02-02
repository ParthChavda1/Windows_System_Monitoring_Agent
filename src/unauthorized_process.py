from src.alert_engine import raise_alert
from src.service_audit import SUSPICIOUS_PATH_KEYWORDS

TRUSTED_DIRECTORIES = [
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\"
]

def load_list(file_path):
    with open(file_path, "r") as f:
        return {line.strip().lower() for line in f if line.strip()}

def is_trusted_path(path):
    return any(path.startswith(td) for td in TRUSTED_DIRECTORIES)

def detect_unauthorized_processes(processes):
    whitelist = load_list("config/whitelist.txt")
    blacklist = load_list("config/blacklist.txt")

    seen = set()  # dedup (name, path)

    for proc in processes:
        name = (proc.get("name") or "").lower()
        path = (proc.get("path") or "").lower()

        if not name or not path:
            continue

        key = (name, path)
        if key in seen:
            continue
        seen.add(key)

        # 1️⃣ Blacklisted → HIGH
        if name in blacklist:
            raise_alert(
                alert_type="Blacklisted Process",
                severity="HIGH",
                details=f"Blacklisted process detected: {name} | Path: {path}"
            )
            continue

        # 2️⃣ Suspicious path → HIGH
        if any(keyword in path for keyword in SUSPICIOUS_PATH_KEYWORDS):
            raise_alert(
                alert_type="Suspicious Process Path",
                severity="HIGH",
                details=f"Process running from suspicious path: {name} | Path: {path}"
            )
            continue  # VERY IMPORTANT

        # 3️⃣ Unknown + user-writable path → LOW
        if name not in whitelist and not is_trusted_path(path):
            raise_alert(
                alert_type="Unknown Process",
                severity="LOW",
                details=f"Unknown process detected: {name} | Path: {path}"
            )
