# Security Incident Report — SSH Failed Login Activity

## Incident Summary
Suspicious SSH authentication activity was detected in Splunk Enterprise involving multiple failed login attempts from external IP addresses. The behavior is consistent with brute-force or password spraying attacks.

---

## Detection Method
The incident was identified using Splunk queries analyzing authentication logs.

Key detection search:
```spl
index=auth_logs "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 5
| sort - count
```

## Observations
-Multiple failed login attempts detected
-Single IP addresses targeting multiple systems
-Repeated authentication failures in short time window
-Common targeted usernames include: root, admin, and invalid users

---

## Impact Assessment
-No confirmed successful login observed
-High probability of brute-force or password spraying attempt
-SSH service was actively targeted from external IPs

---

## Investigation Summary
-Further analysis in Splunk showed:
-Attack traffic originated from multiple public IPs
-Some IPs generated significantly higher failed login counts
-Activity occurred within short time intervals, indicating automation

---

## Actions Taken
-Created alert for detecting brute-force attempts
-Built dashboard for monitoring authentication failures
-Identified top attacking IPs and targeted usernames
-Extracted key fields using regex for analysis

---

## Recommendations
-Enforce account lockout after repeated failed logins
-Implement MFA for SSH access
-Restrict SSH access using firewall rules
-Continuously monitor authentication logs in Splunk

## Conclusion
This incident demonstrates a simulated brute-force attack scenario successfully detected using Splunk Enterprise. The implemented detections, dashboards, and alerts provide early visibility into malicious authentication activity.
