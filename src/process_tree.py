from src.alert_engine import raise_alert

SUSPICIOUS_CHAINS = {
    "winword.exe": ["cmd.exe", "powershell.exe"],
    "excel.exe": ["cmd.exe", "powershell.exe"],
    "outlook.exe": ["cmd.exe", "powershell.exe"],
    "chrome.exe": ["cmd.exe"],
    "firefox.exe": ["cmd.exe"]
}

def analyze_parent_child(processes):
    pid_map = {p["pid"]:p for p in processes}
    
    for proc in processes:
        parent_pid = proc.get("ppid")
        child_name = proc.get("name","").lower()
        
        parent = pid_map.get(parent_pid)
        if not parent:
            continue
        
        parent_name  = parent.get("name","").lower()
        if parent_name in SUSPICIOUS_CHAINS:
            if child_name in SUSPICIOUS_CHAINS[parent_name]:
                details = (
                    f"Suspicious Parent Child Chain Detected:"
                    f"{parent_name}-> {child_name}"
                    f"(PID {parent_pid} -> {proc})"
                )
                raise_alert(
                    alert_type="Suspicious Parent Child Process",
                    severity="HIGH",
                    details=details
                )
            
                
                