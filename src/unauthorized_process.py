from src.alert_engine import raise_alert

SUSPICIOUS_PATH_KEYWORDS = [
    "//temp//",
    "//appdata//",
    "//downloads//",
]

def load_list(file_path):
    with open(file_path,"r") as f:
        return {line.strip().lower() for line in f if line.strip()}
    
def detect_unauthorized_processes(processes):
    whitelist = load_list("config/whitelist.txt")
    blacklist = load_list("config/blacklist.txt")
    
    for proc in processes:
        name = (proc.get("name") or "").lower()
        path = (proc.get("path") or "").lower()
        
        if name in blacklist:
            raise_alert(
                alert_type="Blacklisted Process",
                severity="HIGH",
                details=f"Blacklisted process detected: {name} | Path: {path}" 
            )
            continue
        
        for keyword in SUSPICIOUS_PATH_KEYWORDS:
            if keyword in path:
                raise_alert(
                    alert_type="Suspicious Process Path",
                    severity= "HIGH",
                    details=f"Process running from suspicious path: {name} | Path: {path}"
                )
                break
            
        if name and name not in whitelist:
            raise_alert(
                alert_type="Unknown Process",
                severity="LOW",
                details=f"Unknown process detected: {name} | Path:{path}"
            )
            