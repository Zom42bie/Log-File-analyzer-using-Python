import re
import pandas as pd
import matplotlib.pyplot as plt

# -------------------------------
# 1. CONFIGURATION
# -------------------------------

APACHE_LOG = 'logs/apache.log'
BLACKLIST_FILE = 'blacklist/blacklist.csv'
OUTPUT_FILE = 'outputs/suspicious_report.csv'

# -------------------------------
# 2. REGEX PATTERN (Apache)
# -------------------------------

# Example: 192.168.1.1 - - [25/Jul/2025:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1043
log_pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d{3})'

# -------------------------------
# 3. PARSE LOG
# -------------------------------

data = []

with open(APACHE_LOG, 'r') as f:
    for line in f:
        match = re.search(log_pattern, line)
        if match:
            ip = match.group(1)
            datetime = match.group(2)
            request = match.group(3)
            status = match.group(4)
            data.append([ip, datetime, request, status])

df = pd.DataFrame(data, columns=['IP', 'Date', 'Request', 'Status'])

print("Sample parsed log entries:")
print(df.head())

# -------------------------------
# 4. ANALYZE - Top IPs
# -------------------------------

print("\nTop 10 IPs by number of requests:")
top_ips = df['IP'].value_counts().head(10)
print(top_ips)

# -------------------------------
# 5. PLOT - Top IPs
# -------------------------------

plt.figure(figsize=(10, 6))
top_ips.plot(kind='bar', color='skyblue')
plt.title('Top 10 IPs by Requests')
plt.xlabel('IP Address')
plt.ylabel('Number of Requests')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# -------------------------------
# 6. CROSS-CHECK BLACKLIST
# -------------------------------

# Example blacklist.csv should have column "IP"
try:
    blacklist = pd.read_csv(BLACKLIST_FILE)
    print("\nBlacklisted IPs found in logs:")
    suspicious = df[df['IP'].isin(blacklist['IP'])]
    print(suspicious)

    # -------------------------------
    # 7. EXPORT REPORT
    # -------------------------------

    suspicious.to_csv(OUTPUT_FILE, index=False)
    print(f"\nSuspicious report saved to: {OUTPUT_FILE}")

except FileNotFoundError:
    print("\nNo blacklist file found. Skipping blacklist check.")

