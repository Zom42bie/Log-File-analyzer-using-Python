# Log-File-analyzer-using-Python
Detect suspicious access patterns in Apache &amp; SSH logs using Python, pandas, and regex. Visualizes threats, checks IPs against blacklists, and exports incident reports. 
# Log File Analyzer for Intrusion Detection

A simple Python tool to help system admins detect brute-force attacks, scanning, and suspicious IPs in Apache and SSH log files.  
It uses `pandas` for data handling, `regex` for parsing logs, and `matplotlib` for basic visualization.

**Key Features**
- Parses Apache access logs & SSH authentication logs
- Detects brute force and suspicious activity patterns
- Cross-checks with a public IP blacklist
- Exports flagged incidents to a CSV report
- Generates simple graphs to visualize suspicious access trends
