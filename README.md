* * *

Windows Service & Process Monitoring Agent
==========================================

A Python-based Windows monitoring agent that analyzes running processes and startup services to detect suspicious, unauthorized, or anomalous activity using rule-based detection and structured logging.

This project focuses on **defensive security (Blue Team)** concepts such as process auditing, persistence detection, process tree analysis, and alert generation.

* * *

Features
--------

*   Monitors running Windows processes
*   Generates process tree relationships
*   Audits startup services for persistence detection
*   Detects:
    *   Blacklisted processes
    *   Processes running from suspicious locations
    *   Unauthorized processes not present in whitelist
*   Supports controlled execution from AppData using allow rules
*   Severity-based alert classification (HIGH / LOW)
*   Separate activity and alert logs
*   Lightweight user-space monitoring agent

* * *

Prerequisites
-------------

*   Windows 10 / 11
*   Python 3.9 or higher
*   Administrator privileges (recommended for service enumeration)

* * *

Environment Setup (Recommended)
-------------------------------

Create and activate a virtual environment before installing dependencies.

```bash
python -m venv venv
```

Activate the virtual environment:

**Windows (PowerShell):**

```bash
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

* * *

Usage
-----

Run the monitoring agent from the project root:

```bash
python main.py
```

Logs will be generated automatically:

*   `logs/activity.log` – General system monitoring
*   `logs/alerts.log` – Security alerts with severity classification

* * *

Detection Logic Overview
------------------------

The monitoring agent applies rule-based detection using the following logic:

### Blacklist Detection

Processes explicitly listed in `blacklist.txt` trigger **HIGH severity alerts**.

### Suspicious Path Detection

Processes executing from user-writable locations such as `AppData` or `Temp` trigger **HIGH severity alerts**, unless explicitly allowed.

### Allowed AppData Handling

Legitimate applications that execute from `AppData` (e.g., VS Code, updaters) can be permitted using:

```
config/allowed_appdata.txt
```

This prevents unnecessary high-severity alerts while maintaining visibility.

### Unknown Process Detection

Processes not present in the whitelist are logged as **LOW severity alerts** for monitoring and review.

* * *

Configuration Files
-------------------

All detection rules are configurable without modifying code:

*   `config/whitelist.txt` – Trusted process names
*   `config/blacklist.txt` – Explicitly blocked process names
*   `config/allowed_appdata.txt` – Legitimate processes allowed to run from AppData

* * *

Alert Severity Levels
---------------------

| Severity | Description |
| --- | --- |
| HIGH | Suspicious or unauthorized activity requiring attention |
| LOW | Informational alert for unknown but non-malicious activity |

* * *

Logs and Reports
----------------

*   Activity and alert logs are stored in the `logs/` directory
*   A consolidated execution report can be generated in the `reports/` directory

* * *

Limitations
-----------

*   Rule-based detection only (no ML or behavioral heuristics)
*   User-space monitoring (no kernel hooks)
*   Requires manual tuning of whitelist and allowed AppData entries

* * *

Disclaimer
----------

This project is intended for **educational and defensive security purposes only**.  
It does not perform prevention, remediation, or malware removal.

* * *

Author
------

**Parth Chavda**  
Bachelor of Engineering – Computer Engineering

* * *
