# Windows Authentication Log Analyzer

## Overview
A lightweight defensive security tool that analyzes Windows authentication events to identify potentially suspicious login activity. The project uses PowerShell to export Windows Security events and Python to aggregate authentication activity, identify repeated failed logons, and generate a CSV report.

## Objectives
- Analyze successful logon events (Event ID 4624).
- Analyze failed logon events (Event ID 4625).
- Aggregate failed attempts by username and source IP address.
- Flag five or more failed attempts from the same source IP within a ten-minute window.
- Export potential alerts to CSV for further investigation.

## Technologies
- Windows 11 Pro
- PowerShell
- Python 3
- Windows Security Event Log
- CSV

## Project Structure
```text
windows-authentication-log-analyzer/
├── data/
├── reports/
├── export_events.ps1
├── analyzer.py
├── .gitignore
└── README.md

```

## Requirements

* Windows with access to the Security event log.
* Python 3.
* Permission to read the required Windows Security events. No third-party Python packages are required.

## Usage

1. Clone or download this repository.
2. Open PowerShell in the project directory.
3. Run the event export script.
4. Run the analyzer:
```bash
python analyzer.py

```


5. Review the terminal output and the generated report at `reports/suspicious_sources.csv`.

## Detection Logic

The analyzer identifies failed logons and groups them by source IP address. Five or more failures from the same IP within a ten-minute window generate a potential brute-force alert. This is a heuristic for triage, not a definitive determination of malicious activity.

## Limitations

* Only Event IDs 4624 and 4625 are analyzed.
* Detection depends on the availability and completeness of Windows Security logs.
* Missing source IP addresses limit IP-based correlation.
* Distributed attacks and successful authentication followed by suspicious activity are not covered.
* Repeated alerts may occur for overlapping detection windows.

## Testing

Use synthetic authentication events to validate the detection logic. Do not publish real authentication logs or sensitive host information.

## Disclaimer

This project is intended for defensive security learning and authorized lab environments. Alerts require further investigation before conclusions are drawn.

## Future Improvements

* Add time-window alert deduplication.
* Include logon types and failure status codes.
* Correlate failed attempts with subsequent successful logons.
* Add unit tests and structured logging.
* Support EVTX input directly.