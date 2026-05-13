#  Failed Login Detection using Splunk

##  Overview
This project demonstrates how to detect suspicious login activity using Splunk Enterprise by analyzing SSH authentication logs.  
It focuses on identifying brute-force attacks, password spraying, and unusual authentication behavior.

The project simulates a basic SOC (Security Operations Center) monitoring workflow.

---

##  Objectives
- Detect multiple failed login attempts
- Identify brute-force attack patterns
- Analyze targeted usernames
- Visualize attack trends using dashboards
- Create alerting rules for suspicious activity

---

##  Tools Used
- Splunk Enterprise (SIEM Platform)
- OpenSSH authentication logs
- SPL (Search Processing Language)

---

##  Dataset
Sample SSH authentication logs from LogHub:
https://github.com/logpai/loghub/tree/master/SSH](https://github.com/logpai/loghub/blob/master/OpenSSH/OpenSSH_2k.log

---

##  Key Detections

### 1. Basic Failed Login Detection
```spl
index=auth_logs "Failed password"

```
### 2. Brute Force Detection (by IP)
```spl
index=auth_logs "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 5
| sort - count
```
### 3. Targeted User Analysis
```spl
index=auth_logs "Failed password"
| rex "for (invalid user )?(?<user>\w+)"
| stats count by user
| sort - count
```

### 4. Attack Trend Over Time
```spl
index=auth_logs "Failed password"
| timechart span=1h count
```
---

## Dashboards Created
Top attacking IP addresses
Failed login trend over time
Most targeted user accounts

---

## Alerting
A scheduled alert was created in Splunk to detect IP addresses generating multiple failed login attempts, indicating possible brute-force attacks.

---

## Screenshots
Screenshots of Splunk searches, dashboards, and alerts are available in the screenshots/ folder.

---

## Key Learnings
SIEM log analysis
SPL querying and filtering
Regex-based field extraction
Security alert creation
Dashboard visualization
Basic SOC workflow understanding

---

## Conclusion
This project demonstrates a real-world security monitoring scenario using Splunk Enterprise. It simulates how SOC analysts detect and respond to authentication-based attacks using log analysis and alerting.

---

## Author
Student cybersecurity project for SOC analyst learning path.
