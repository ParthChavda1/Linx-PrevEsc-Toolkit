
* * *

Linux Privilege Escalation Audit Toolkit
========================================

Description
-----------

The **Linux Privilege Escalation Audit Toolkit** is a detection-only security auditing tool designed to identify common Linux privilege escalation vectors caused by misconfigurations, insecure permissions, and unsafe system services.

The tool automates **real-world enumeration techniques** used during Linux privilege escalation assessments while **strictly avoiding exploitation**. It is intended for learning, defensive security analysis, and controlled lab environments.

* * *

Key Objectives
--------------

*   Automate Linux privilege escalation enumeration
*   Identify misconfigurations exploitable by non-root users
*   Simulate attacker-style reconnaissance logic
*   Provide clear, actionable security findings
*   Maintain strict **detection-only** behavior

* * *

Features
--------

### System Enumeration

*   Current user and group identification
*   Kernel and OS information
*   Root vs non-root execution context

### SUID / SGID Binary Analysis

*   Enumeration of SUID/SGID binaries
*   Detection of high-risk binaries
*   GTFOBins-style exploitability logic
*   Validation against **current user permissions**

### Permission Misconfiguration Scan

*   Root-owned world-writable files
*   Group-writable root files
*   Writable configuration files
*   Exploitability verification for non-root users

### systemd Service & Timer Scan

*   Writable `.service` and `.timer` files
*   Unsafe ownership and permissions
*   PATH injection risks via `ExecStart`
*   Identification of persistence vectors
*   False-positive-aware validation

### Cron Job Analysis

*   Root cron job enumeration
*   Writable cron scripts
*   Insecure scheduled execution paths

### Kernel Vulnerability Awareness

*   Kernel version detection
*   Known vulnerability references
*   Risk classification (no exploitation)

* * *


Requirements
------------

*   Linux operating system
*   Python 3.8 or later
*   Standard Linux utilities (systemd, cron, procfs)

* * *

Installation
------------

### Clone the Repository

```bash
git clone https://github.com/yourusername/linux-privesc-audit-toolkit.git
cd linux-privesc-audit-toolkit
```

### Create a Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

* * *

Usage
-----

Run the tool from the project root:

```bash
python main.py
```

### Execution Notes

*   **Run as a non-root user** for accurate privilege escalation detection.
*   Running as root may hide misconfigurations exploitable by normal users.
*   The tool does **not** modify system state.

* * *

Report Generation
-----------------

The toolkit supports **structured report generation** to allow further analysis, sharing, and archival.

### Supported Report Formats

#### 1\. JSON Report (Machine-Readable)

Used for:

*   Automation pipelines
*   Further analysis
*   SIEM ingestion
*   Custom dashboards

**Output File:**

```
reports/report.json
```

**Example Structure:**

```json
{
  "scan_metadata": {
        "scan_time": "2026-01-27T05:45:00.466231Z",
        "tool_name": "Linux PrivEsc Audit Tool",
        "tool_version": "1.0",
        "scan_type": "Local Privilege Escalation Assessment"
    },
  "system_information": {
        "user": "kali",
        "uid": 1000,
        "is_root": false,
        "os": "Linux",
        "kernel": "6.12.38+kali-amd64",
        "architecture": "x86_64"
  },
  "summary": {
        "total_findings": 8,
        "severity_breakdown": {
            "CRITICAL": 0,
            "HIGH": 6,
            "MEDIUM": 1,
            "LOW": 1
        },
        "overall_risk": "HIGH"
    },
    "findings": [
        {
            "id": "FND-001",
            "category": "SUID Binary",
            "severity": "HIGH",
            "title": "Suspicious SUID binary detected",
            "affected_component": "/home/kali/suid_test/fakefind.sh",
            "exploitation_possibility": "SUID binary may allow execution of commands with root privileges if abused.",
            "suggested_mitigation": "Review necessity of SUID bit, restrict permissions or remove the binary."
        },
        {
            "id": "FND-002",
            "category": "Weak File Permissions",
            "severity": "HIGH",
            "title": "Cron executes writable script as root",
            "affected_component": "/opt/backup.sh",
            "exploitation_possibility": "Cron runs as root automatically",
            "suggested_mitigation": "Restrict permissions and ensure root-only ownership."
        }
      ]
}
```

* * *

#### 2\. TXT Report (Human-Readable)

Used for:

*   Manual review
*   Submissions
*   Incident documentation
*   Offline analysis

**Output File:**

```
reports/report.txt
```

**Example Content:**

```
LINUX PRIVILEGE ESCALATION ASSESSMENT REPORT
=======================================================
Tool Name     : Linux PrivEsc Audit Tool
Tool Version  : 1.0
Scan Type     : Local Privilege Escalation Assessment
Scan Time     : 2026-01-27T05:45:00.466231Z

SYSTEM INFORMATION
-------------------------
User          : kali
UID           : 1000
Is Root       : False
Operating Sys : Linux
Kernel        : 6.12.38+kali-amd64
Architecture  : x86_64

EXECUTIVE SUMMARY
-------------------------
Total Findings : 8
Severity Breakdown:
  CRITICAL : 0
  HIGH     : 6
  MEDIUM   : 1
  LOW      : 1
Overall Risk   : HIGH

DETAILED FINDINGS
=======================================================
Finding ID    : FND-001
Category      : SUID Binary
Severity      : HIGH
Title         : Suspicious SUID binary detected
Affected Item : /home/kali/suid_test/fakefind.sh

Exploitation Possibility:
  SUID binary may allow execution of commands with root privileges if abused.

Suggested Mitigation:
  Review necessity of SUID bit, restrict permissions or remove the binary.
-------------------------------------------------------
Finding ID    : FND-002
Category      : Weak File Permissions
Severity      : HIGH
Title         : Cron executes writable script as root
Affected Item : /opt/backup.sh

Exploitation Possibility:
  Cron runs as root automatically

Suggested Mitigation:
  Restrict permissions and ensure root-only ownership.
```

* * *

How to Generate Reports
-----------------------

Reports are generated automatically when the tool runs.

```bash
python main.py
```

After execution, reports will be available in:

```
reports/
├── report.json
└── report.txt
```

* * *

Learning Outcomes
-----------------

This project demonstrates:

*   Linux privilege escalation fundamentals
*   Permission and ownership abuse vectors
*   systemd and cron attack surfaces
*   Secure auditing practices
*   Automation of attacker enumeration logic
*   Defensive mindset and ethical boundaries

* * *

Limitations
-----------

*   Does not exploit detected vulnerabilities
*   Does not guarantee full system coverage
*   Kernel vulnerability checks are informational only

* * *

Disclaimer
----------

This project is intended **only for educational and defensive security purposes**.  
Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.

* * *

Author
------

**Parth Chavda**  
Computer Engineering | Security & Systems  
Linux Security • Privilege Escalation • Defensive Automation

* * *



