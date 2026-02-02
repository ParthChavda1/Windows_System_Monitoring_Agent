import ast
from collections import Counter
import json

ALERT_LOG = "logs/alerts.log"
REPORT_FILE = "reports/final_report.txt"

def generate_report(total_processes):
    alerts = []
    severities = []

    with open(ALERT_LOG, "r") as f:
        for line in f:
            try:
                data = line.strip().split("| {")[1]
                data = ("{" + data.strip()).replace("'",'"')
                alert = json.loads(data)
                # alert1 = ast.literal_eval(data)
                alerts.append(alert)
                severities.append(alert["severity"])
            except Exception:
                continue

    severity_count = Counter(severities)

    with open(REPORT_FILE, "w") as report:
        report.write("Windows Service & Process Monitoring Agent Report\n")
        report.write("=" * 55 + "\n\n")

        report.write(f"Total Processes Scanned: {total_processes}\n")
        if len(alerts) !=0:
            report.write(f"Total Alerts Generated: {len(alerts)}\n\n")

            report.write("Severity Breakdown:\n")
            for sev, count in severity_count.items():
                report.write(f"  {sev}: {count}\n")

            report.write("\nDetailed Alerts:\n")
            for alert in alerts:
                report.write(f"- [{alert['severity']}] {alert['type']} | {alert['details']}\n")
        else:
            report.write("No Alerts detected.\n")
            report.write("Your System is safe and secure!!")

    return REPORT_FILE