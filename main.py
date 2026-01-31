import psutil
from src.process_monitor import enumerate_process
from src.process_tree import  analyze_parent_child
from src.service_audit import audit_startup_services
from src.unauthorized_process import detect_unauthorized_processes
from src.report_generation import generate_report

def clear_logs():
    open("logs/activity.log", "w").close()
    open("logs/alerts.log", "w").close()

def main():
    clear_logs()
    print("Finding Processes...")
    processes = enumerate_process()
    
    print("Analyzing Suspiciouse Parent child relationship...")
    analyze_parent_child(processes=processes)
    
    print("Analyzing Startup services...")
    audit_startup_services()
    print("Analyzing Unauthorized Processes...")
    detect_unauthorized_processes(processes)
    
    print("Generating Report...")
    report_path = generate_report(len(processes))
    
    print(f"Report Stored at file path: {report_path}")


if __name__ == "__main__":
    main()
