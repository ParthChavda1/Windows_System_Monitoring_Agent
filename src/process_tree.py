from collections import defaultdict

from src.alert_engine import raise_alert


SUSPICIOUS_CHAINS = {
    "winword.exe": ["cmd.exe", "powershell.exe"],
    "excel.exe": ["cmd.exe", "powershell.exe"],
    "outlook.exe": ["cmd.exe", "powershell.exe"],
    "chrome.exe": ["cmd.exe"],
    "firefox.exe": ["cmd.exe"]
}

def build_process_tree(processes):
    tree = defaultdict(list)
    pid_map = {}

    for p in processes:
        pid_map[p["pid"]] = p

    for p in processes:
        parent_pid = p.get("ppid")
        if parent_pid in pid_map:
            tree[parent_pid].append(p)

    return tree, pid_map

def analyze_parent_child(processes):
    tree, pid_map = build_process_tree(processes)

    # Print Parent-child precess tree
    # for parent_pid, children in tree.items():
    #     print(pid_map[parent_pid]["name"], "→",
    #             [c["name"] for c in children])

    for parent_pid, children in tree.items():
        parent = pid_map[parent_pid]
        parent_name = parent["name"].lower()

        if parent_name not in SUSPICIOUS_CHAINS:
            continue

        for child in children:
            child_name = child["name"].lower()

            if child_name in SUSPICIOUS_CHAINS[parent_name]:
                details = (
                    f"Suspicious parent-child chain detected: "
                    f"{parent_name} → {child_name} "
                    f"(PID {parent_pid} → {child['pid']})"
                )

                raise_alert(
                    alert_type="Suspicious Parent-Child Process",
                    severity="HIGH",
                    details=details
                )

                
                