##### **# Failed Login Detection using Splunk**

##### 

##### \## Overview

This project demonstrates detection of suspicious login activity using Splunk Enterprise by analyzing SSH authentication logs.



The goal is to identify brute-force attacks, password spraying, and unusual login patterns.



\---



##### \## Tools Used

\- Splunk Enterprise (SIEM Platform)

\- OpenSSH authentication logs



\---



##### \## Dataset

Sample SSH logs from:

https://github.com/logpai/loghub/tree/master/SSH



\---



##### \## Key Detections



###### 1\. Failed Login Detection

index=auth\_logs "Failed password"



###### 2\. Brute Force Detection

index=auth\_logs "Failed password"

| rex "from (?<src\_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"

| stats count by src\_ip

| where count > 5

| sort - count



###### 3\. Targeted User Analysis

index=auth\_logs "Failed password"

| rex "for (invalid user )?(?<user>\\w+)"

| stats count by user

| sort - count



###### \#Dashboards

Top attacking IP addresses

Failed login trends over time

Most targeted user accounts

Alerting



An alert was configured to detect IPs generating multiple failed login attempts, indicating possible brute-force attacks.



##### Key Skills Learned

SIEM log analysis

SPL querying

Field extraction using regex

Alert creation

Dashboard visualization

Security investigation workflow



##### Conclusion

This project simulates real-world SOC monitoring scenarios and demonstrates foundational skills in security monitoring using Splunk.

