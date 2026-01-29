import psutil
from src.process_monitor import enumerate_process
from src.process_tree import  analyze_parent_child
from src.service_audit import audit_startup_services
from src.unauthorized_process import detect_unauthorized_processes

def clear_logs():
    open("logs/activity.log", "w").close()
    open("logs/alerts.log", "w").close()

def main():
    clear_logs()
    processes = enumerate_process()
    analyze_parent_child(processes=processes)
    audit_startup_services()
    detect_unauthorized_processes(processes)
    

if __name__ == "__main__":
    main()
