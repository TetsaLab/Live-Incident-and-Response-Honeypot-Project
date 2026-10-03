# 🛡️ Live Incident Response Honeypot Lab

## Microsoft Azure | Microsoft Sentinel | Defender for Endpoint | KQL | MySQL | Incident Response

---

## 📌 Project Overview

This project demonstrates an end-to-end cybersecurity incident response workflow using a deliberately exposed honeypot environment hosted in Microsoft Azure.

The objective was to build and secure an internet-facing Windows system, configure security telemetry and detection capabilities, establish a clean baseline, intentionally expose the environment, detect real-world malicious activity, investigate the resulting compromise, contain the affected system, and develop an eradication and recovery strategy.

Rather than analyzing pre-generated logs, this project allowed me to work through the complete security operations lifecycle:

```text
Build
   ↓
Instrument
   ↓
Baseline
   ↓
Detect
   ↓
Expose
   ↓
Investigate
   ↓
Contain
   ↓
Eradicate
   ↓
Recover
   ↓
Report
```

The lab provided hands-on experience with:

- Microsoft Azure
- Microsoft Sentinel
- Microsoft Defender for Endpoint
- Log Analytics Workspace
- Azure Monitor Agent
- Data Collection Rules
- Kusto Query Language (KQL)
- Windows security monitoring
- MySQL security monitoring
- SIEM investigation
- Detection engineering
- Threat hunting
- Network analysis
- Digital forensics
- Incident response
- Containment and recovery
- Incident reporting

---

# 🎯 Project Objectives

The main goals of this project were to:

- Build a functional cloud-based honeypot environment
- Configure endpoint and database telemetry
- Centralize logs within Azure Log Analytics
- Develop Microsoft Sentinel analytics rules before exposure
- Establish a known-good security baseline
- Deliberately expose the system to real internet traffic
- Detect unauthorized authentication attempts
- Identify successful compromises
- Investigate endpoint and database activity
- Correlate events across multiple log sources
- Reconstruct an attacker timeline
- Contain the compromised system
- Compare pre-breach and post-breach forensic artifacts
- Develop an eradication and recovery plan
- Produce a complete incident response report

---

# 🏗️ Lab Architecture

The environment consisted of a Windows virtual machine hosted in Microsoft Azure with a MySQL database installed locally.

Microsoft Defender for Endpoint provided endpoint telemetry, while MySQL audit logs were collected using the Azure Monitor Agent and forwarded into a Log Analytics Workspace.

Microsoft Sentinel was used for detection, alerting, threat hunting, and incident investigation.

## Core Components

| Component | Purpose |
|---|---|
| Azure Windows VM | Internet-facing honeypot |
| MySQL Server | Simulated corporate database |
| Microsoft Defender for Endpoint | Endpoint Detection and Response |
| Microsoft Sentinel | SIEM and incident detection |
| Log Analytics Workspace | Centralized log collection |
| Azure Monitor Agent | Collection of custom logs |
| Data Collection Rule | MySQL log ingestion |
| `MySQLAudit_CL` | Custom MySQL audit log table |
| KQL | Detection and threat hunting |
| Network Security Group | Azure network filtering |
| Windows Firewall | Host-level network protection |

---

## 📷 Architecture Diagram

<img width="464" height="310" alt="image" src="https://github.com/user-attachments/assets/26f870fb-a890-4d11-a9ce-319297e88ff5" />


---

# 🔐 Phase 1 — Build and Harden the Honeypot

The environment was initially created in a secured state.

A Windows virtual machine was deployed in Microsoft Azure with a public IP address, but inbound internet traffic was restricted while the environment was being configured.

The VM was then onboarded into Microsoft Defender for Endpoint so that endpoint telemetry could be collected and analyzed.

## Initial Configuration

- Windows virtual machine deployed in Azure
- Public IP address configured
- Internet access initially restricted
- Strong local credentials configured
- Microsoft Defender for Endpoint onboarding completed
- Device telemetry verified
- System maintained in a hardened state during configuration

---

## 📷 Azure VM

```markdown
![Azure Virtual Machine](images/azure-vm.png)
```

<!-- Add Azure VM screenshot here -->

---

# 🗄️ Phase 2 — Install and Configure MySQL

MySQL Server was installed on the honeypot to simulate a business-critical database system.

A dummy corporate database was imported so that any attacker interaction with the database could be observed and analyzed.

MySQL general logging was enabled to record authentication events, connections, and SQL queries.

## MySQL Log Location

```text
C:\ProgramData\MySQL\MySQL Server 8.0\Data\mysql_general.log
```

The MySQL logs would later be forwarded into Azure Log Analytics.

---

## 📷 MySQL Environment

<img width="519" height="312" alt="image" src="https://github.com/user-attachments/assets/e3383e16-3edf-46b0-8070-171202d9ab77" />


---

# 📡 Phase 3 — Configure Log Collection

The next stage was to centralize security telemetry within the Azure Log Analytics Workspace.

A custom Data Collection Rule was created to collect the MySQL general log using the Azure Monitor Agent.

The logs were ingested into the custom Log Analytics table:

```text
MySQLAudit_CL
```

## MySQL Log Collection Configuration

```text
Log File:
C:\ProgramData\MySQL\MySQL Server 8.0\Data\mysql_general.log

Custom Table:
MySQLAudit_CL

Destination:
LAW-Cyber-Range
```

Once the Data Collection Rule was deployed, I verified that MySQL authentication events and database queries were successfully appearing in Log Analytics.

---

## Example Verification Query

```kql
MySQLAudit_CL
| project TimeGenerated, RawData, _ResourceId
| where _ResourceId endswith "<YOUR-VM-NAME>"
```

---

## 📷 Log Ingestion

```markdown
![MySQL Log Ingestion](images/log-ingestion.png)
```

<img width="877" height="353" alt="image" src="https://github.com/user-attachments/assets/1c14a279-8b4b-424f-8752-4bb522e3c1fd" />


---

# 📊 Security Telemetry

The investigation used telemetry from several Microsoft Defender and Azure data sources.

## Primary Log Sources

```text
DeviceLogonEvents
DeviceProcessEvents
DeviceFileEvents
DeviceRegistryEvents
DeviceNetworkEvents
MySQLAudit_CL
NTANetAnalytics
```

These tables provided visibility into authentication, process execution, file activity, registry changes, network communication, and database activity.

---

# 🛡️ Phase 4 — Detection Engineering

Before exposing the honeypot to the internet, Microsoft Sentinel analytics rules were created.

This was an important part of the project because the environment was still clean when the rules were created.

The goal was to ensure that detection capabilities were already operational before attacker activity began.

---

# 🔎 Detection 1 — Successful Windows Logon

A Microsoft Sentinel analytics rule was created to identify successful authentication to the exposed Windows system.


## Example KQL

```kql
let MyDevice = "<DEVICE-NAME>";

DeviceLogonEvents
| where DeviceName == MyDevice
| where AccountName in~ ("administrator", "guest")
| where ActionType == "LogonSuccess"
| project
    TimeGenerated,
    RemoteIP,
    AccountName,
    DeviceName,
    ActionType,
    LogonType
```

This rule was designed to identify successful authentication to accounts that would later be intentionally exposed.

---

## 📷 Sentinel Windows Authentication Rule

```markdown
![Sentinel Windows Logon Detection](images/windows-logon-detection.png)
```


<img width="946" height="398" alt="image" src="https://github.com/user-attachments/assets/d1d2435a-bfa8-430c-8d93-f1dd538a683b" />


---

# 🔎 Detection 2 — Successful MySQL Authentication

MySQL logs were ingested into Log Analytics as raw text.

Because the events were stored inside the `RawData` field, KQL parsing was required to extract meaningful information.

The query identified:

- Successful database authentication
- Failed database authentication
- Username
- Source IP address
- Connection ID
- Device name
- Authentication result

---

## Example MySQL Authentication Investigation

```kql
let MyDevice = "<DEVICE-NAME>";

let FailedConnections =
MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Access denied"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| distinct ConnectionId;

MySQLAudit_CL
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Connect"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| extend ActionType =
    case(
        RawData has "Access denied", "LogonFailure",
        ConnectionId in (FailedConnections), "Ignore",
        "LogonSuccess"
    )
| where ActionType != "Ignore"
| extend Username =
    replace_string(
        tostring(split(tostring(split(RawData,"@")[0]), " ")[-1]),
        "'",
        ""
    )
| extend IpAddress =
    replace_string(
        tostring(split(split(RawData,"@")[1], " ")[0]),
        "'",
        ""
    )
| project
    TimeGenerated,
    DeviceName,
    Username,
    IpAddress,
    ActionType,
    RawData
| order by TimeGenerated desc
```

---

## 📷 MySQL Authentication Detection

```markdown
![MySQL Authentication Detection](images/mysql-auth-detection.png)
```


<img width="674" height="302" alt="image" src="https://github.com/user-attachments/assets/04435f34-6de7-4e11-8825-e5588f3a203c" />


---

# 🧪 Phase 5 — Establish a Clean Baseline

Before deliberately exposing the honeypot, I verified that:

- Defender telemetry was being collected
- MySQL logs were being ingested
- Sentinel analytics rules were enabled
- No unexpected successful authentication events were occurring
- The environment represented a known-good baseline

This provided a reference point that could later be compared with post-compromise activity.

---

# ⚠️ Phase 6 — Deliberate Exposure

Once logging and detections were confirmed, the honeypot was deliberately weakened and exposed to the public internet.

The purpose was to attract unsolicited real-world attacker activity inside a controlled cybersecurity training environment.

The exposure process included intentionally weakening selected security controls and making the system discoverable from the internet.

> **Important:** These actions were performed only inside an isolated training environment containing simulated data.

## Exposure Timestamp

```text
2026-09-12T02:16:00.2844301Z
```

This timestamp established the beginning of the incident investigation window.

---

## 📷 Exposure Configuration

```markdown
![Honeypot Exposure](images/honeypot-exposure.png)
```

<!-- Add NSG / firewall / exposure screenshot -->

---

# 🚨 Phase 7 — Detect the Breach

Once exposed, the system was monitored for attacker activity.

Microsoft Sentinel analytics rules and Defender telemetry were used to identify:

- Authentication attempts
- Successful logons
- Database authentication
- Database queries
- Process execution
- File activity
- Registry activity
- Network communication
- Denied outbound connections

---

## Windows Authentication Hunting

```kql
let MyDevice = "<DEVICE-NAME>";
let ServerVulnerableDateTime = todatetime("2026-09-12T02:16:00.2844301Z");

DeviceLogonEvents
| where TimeGenerated > ServerVulnerableDateTime
| where DeviceName == MyDevice
| where AccountName in~ ("administrator", "guest")
| project
    TimeGenerated,
    RemoteIP,
    AccountName,
    DeviceName,
    ActionType,
    LogonType
| order by TimeGenerated desc
```

---

## 📷 Security Alert

```markdown
![Security Alert](images/security-alert.png)
```


<img width="679" height="297" alt="image" src="https://github.com/user-attachments/assets/198ddbca-c365-4aef-8525-de54017ac419" />


---

# 🔍 Phase 8 — Threat Hunting and Investigation

Once suspicious activity was identified, I began reconstructing what occurred inside the environment.

The investigation focused on determining:

- When malicious activity began
- Which accounts were targeted
- Which authentication attempts succeeded
- Which IP addresses interacted with the system
- Which commands were executed
- Which processes were created
- Which files were created or modified
- Whether registry changes occurred
- Whether persistence was established
- Which network destinations were contacted
- What activity occurred inside the MySQL database

---

# 🔎 MySQL Query Investigation

Database activity was investigated using the `MySQLAudit_CL` table.

## KQL Query

```kql
MySQLAudit_CL
| where RawData has "Query"
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| extend ActionType = "Query"
| extend Query = split(RawData, "Query")[1]
| project
    TimeGenerated,
    DeviceName,
    ActionType,
    Query,
    RawData
| order by TimeGenerated desc
```

This provided visibility into SQL commands executed by unauthorized users.

---

## 📷 Database Activity

```markdown
![MySQL Attacker Queries](images/mysql-attacker-queries.png)
```

<img width="680" height="301" alt="image" src="https://github.com/user-attachments/assets/13a90691-6826-4b49-8722-3fa6d52805ea" />


---

# 🖥️ Endpoint Investigation

Microsoft Defender for Endpoint telemetry was used to investigate system activity.

## Defender Tables Used

```text
DeviceLogonEvents
DeviceProcessEvents
DeviceFileEvents
DeviceRegistryEvents
DeviceNetworkEvents
```

These data sources were correlated to reconstruct the actions performed on the compromised endpoint.

---

# 🌐 Network Investigation

Network telemetry was also analyzed to identify inbound and outbound communication involving the honeypot.

## Example Query

```kql
let MyDevice = "<DEVICE-NAME>";

NTANetAnalytics
| where isnotempty(SrcVm)
| where SrcVm endswith MyDevice
| where DeniedOutFlows >= 1
| project
    TimeGenerated,
    DeviceName = MyDevice,
    FlowType,
    FlowStatus,
    SrcIp,
    SrcPorts,
    DestIp,
    DestPort
```

The lab environment restricted outbound activity so that attempted attacker command-and-control, pivoting, or other outbound communication could be observed without allowing unrestricted external access.

---

## 📷 Network Investigation

```markdown
![Network Investigation](images/network-investigation.png)
```


<img width="658" height="288" alt="image" src="https://github.com/user-attachments/assets/66642730-cb9f-4fbe-af01-9bb24cc28da1" />


---

# 🕒 Incident Timeline

> Replace or expand the table below using the timeline from your final investigation report.

| Time | Event | Source |
|---|---|---|
| 2026-09-12 02:16 UTC | Honeypot exposed to the internet | Lab Notes |
| TBD | Initial scanning / authentication activity observed | Defender |
| TBD | Multiple failed authentication attempts observed | DeviceLogonEvents / MySQL |
| TBD | Successful unauthorized authentication | Defender / MySQL |
| TBD | Database enumeration begins | MySQLAudit_CL |
| TBD | Suspicious SQL queries executed | MySQLAudit_CL |
| TBD | Endpoint activity investigated | MDE |
| TBD | File / process / registry activity analyzed | MDE |
| TBD | Outbound network activity reviewed | NTANetAnalytics |
| 2026-09-13 22:49 UTC | Compromised system isolated | Defender for Endpoint |

---

# 📷 Incident Timeline Screenshot

```markdown
![Incident Timeline](images/incident-timeline.png)
```

---

# 🚧 Phase 9 — Containment

After sufficient evidence had been collected, the compromised virtual machine was isolated using Microsoft Defender for Endpoint.

## Isolation Timestamp

```text
2026-09-13T22:49:24.8563108Z
```

Device isolation prevented the compromised host from continuing to communicate with other systems while preserving access for investigation.

---

## 📷 Device Isolation

```markdown
![Defender Device Isolation](images/device-isolation.png)
```


<img width="439" height="297" alt="image" src="https://github.com/user-attachments/assets/d9c8a171-347c-4cc0-aa1a-bc01339e9240" />


---

# 🧬 Forensic Investigation

Microsoft Defender investigation packages were collected before and after the breach.

The two packages were compared to identify changes introduced during the compromise.

## Areas Compared

- Running processes
- Loaded modules
- Services
- Drivers
- Scheduled tasks
- Registry persistence
- Startup locations
- Local users
- Group membership
- Network connections
- Listening ports
- File system changes
- Event logs
- Recently created executables
- Hosts file
- Other persistence mechanisms

---

## 📷 Pre-Breach vs Post-Breach Comparison

[DFIR Comparative Analysis](https://docs.google.com/document/d/1Bv684BmwiGMRnIj5lrVv0wV5Pr2c9isX/edit?usp=sharing&ouid=103047111509812865481&rtpof=true&sd=true)


---

# 🧹 Phase 10 — Eradication and Recovery

Because the honeypot was intentionally exposed and both the Windows system and MySQL database were treated as compromised, the safest recovery approach was to rebuild the system from a trusted state.

## Recovery Strategy

The recovery plan included:

- Restore restrictive Azure NSG rules
- Re-enable Windows Firewall
- Remove exposed administrative accounts
- Disable unnecessary local accounts
- Replace weak credentials
- Restrict remote database access
- Reset database credentials
- Perform a full malware scan
- Restore database data from a known-good backup
- Validate security controls
- Verify endpoint monitoring
- Verify logging
- Confirm Sentinel detection rules
- Return the system to a hardened configuration

---

# 📊 Key Findings

## 1. Confirmed Unauthorized MySQL Root Access

The investigation confirmed repeated remote authentication to the MySQL `root` account from external IP addresses.

The first confirmed malicious activity was associated with `64.89.163.93`, which established multiple successful root sessions immediately before destructive database activity began.

Additional successful MySQL root authentication was later observed from:

- `213.209.159.115`
- `45.128.199.82`

This confirmed that the database was directly accessible from the public internet and that privileged credentials were successfully used by unauthorized external systems.

---

## 2. Database Enumeration and Data Access

After gaining access to the MySQL server, the attacker began enumerating the database environment and accessing stored information.

Observed activity included:

- Database enumeration
- Table enumeration
- `SELECT` queries against database records
- Inspection of database structure
- Access to application data

The successful execution of `SELECT` statements confirmed that the attacker obtained read-level access to database content.

### Confidentiality Impact

**Potentially Impacted**

Although database records were accessed, the available evidence did not confirm that bulk data was successfully exfiltrated from the environment.

---

## 3. Destructive SQL Activity

The attacker executed multiple destructive SQL commands against the database environment.

Confirmed activity included:

```sql
DROP TABLE credentials
DROP TABLE customers
DROP TABLE orders
DROP TABLE payments

DROP DATABASE lnp_corp
DROP DATABASE sakila
DROP DATABASE world
```


# 🧠 Skills Developed

This project strengthened my practical cybersecurity experience in the following areas:

## Security Operations

- SIEM monitoring
- Alert investigation
- Security telemetry analysis
- Incident triage
- Event correlation

## Threat Hunting

- KQL development
- Authentication analysis
- Process investigation
- Network investigation
- Database auditing

## Detection Engineering

- Microsoft Sentinel analytics rules
- Custom log parsing
- Alert logic development
- Entity mapping
- Baseline validation

## Incident Response

- Detection
- Analysis
- Containment
- Eradication
- Recovery
- Reporting

## Digital Forensics

- Pre-breach baseline comparison
- Post-breach forensic analysis
- Process analysis
- Persistence analysis
- File system analysis
- Registry investigation
- Network connection analysis

## Cloud Security

- Microsoft Azure
- Azure Virtual Machines
- Network Security Groups
- Log Analytics
- Azure Monitor Agent
- Data Collection Rules
- Microsoft Defender

---

# 🧰 Technologies Used

| Technology | Usage |
|---|---|
| Microsoft Azure | Cloud infrastructure |
| Windows 11 | Honeypot operating system |
| Microsoft Sentinel | SIEM |
| Microsoft Defender for Endpoint | Endpoint Detection and Response |
| Log Analytics | Security log storage |
| Azure Monitor Agent | Log collection |
| Data Collection Rules | Custom MySQL log ingestion |
| MySQL | Database honeypot |
| KQL | Detection and investigation |
| PowerShell | Windows administration |
| Azure NSG | Network filtering |

---

# 📂 Project Artifacts

## Incident Response Report

```markdown
[View Incident Response Report](reports/incident-response-report.pdf)
```

---

## Executive Summary

```markdown
[View Executive Summary](reports/executive-summary.pdf)
```

---

## Forensic Investigation

```markdown
[View Forensic Analysis](reports/forensic-analysis.pdf)
```

---

# 🔎 KQL Queries

The KQL queries used during this project are available in the `queries` directory.

```markdown
[View Detection and Threat Hunting Queries](queries/)
```

Recommended files:

```text
windows-logon-detection.kql
mysql-authentication.kql
mysql-query-analysis.kql
device-process-investigation.kql
network-analysis.kql
threat-hunting.kql
```

---

# 📜 Log Samples

Selected sanitized log samples can be included in the repository to demonstrate how the investigation was performed.

```markdown
[View Sanitized Log Samples](logs/)
```

Recommended samples:

```text
mysql-auth-sample.csv
mysql-query-sample.csv
device-logon-sample.csv
device-process-sample.csv
network-events-sample.csv
```

---
# 📸 Additional Screenshots

## Microsoft Sentinel Incident

```markdown
![Microsoft Sentinel Incident](images/sentinel-incident.png)
```

---

## Microsoft Defender Investigation

```markdown
![Microsoft Defender Investigation](images/defender-investigation.png)
```

---

## MySQL Authentication Activity

```markdown
![MySQL Authentication Activity](images/mysql-authentication.png)
```

---

## KQL Threat Hunting

```markdown
![KQL Threat Hunting](images/kql-investigation.png)
```

---

## Process Investigation

```markdown
![Process Investigation](images/process-investigation.png)
```

---

## Network Analysis

```markdown
![Network Analysis](images/network-analysis.png)
```

---

# 📈 Project Workflow

```text
┌─────────────────────────┐
│ Build Azure Honeypot    │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Install MySQL           │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Configure Logging       │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Send Logs to Azure      │
│ Log Analytics           │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Create Sentinel         │
│ Detection Rules         │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Establish Baseline      │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Expose Honeypot         │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Detect Attack Activity  │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Threat Hunt             │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Reconstruct Incident    │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Contain System          │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Forensic Comparison     │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Eradicate & Recover     │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Incident Report         │
└─────────────────────────┘
```

---

# 💡 Lessons Learned

This project reinforced several important cybersecurity concepts.

### Detection Before Exposure

Security telemetry and detections should be established before systems are exposed to risk.

Creating detections before exposure provided a known baseline and ensured malicious activity could be detected immediately.

### Centralized Logging Is Critical

Endpoint, database, and network telemetry provided different pieces of the incident.

Correlating multiple data sources made it possible to reconstruct a much more complete picture of attacker activity.

### Raw Logs Require Investigation

Security logs rarely provide a complete answer by themselves.

KQL parsing and correlation were required to transform raw events into meaningful incident evidence.

### Baselines Improve Forensic Analysis

Collecting information before the breach made it possible to compare the system before and after compromise.

### Containment Is Only One Part of Incident Response

Isolating the compromised system stopped additional activity, but investigation, eradication, recovery, and reporting were equally important.

---

# 🎯 Key Takeaway

This project allowed me to experience the complete cybersecurity incident response lifecycle instead of only analyzing pre-generated logs.

I:

- Built the cloud environment
- Configured endpoint monitoring
- Ingested custom application logs
- Developed detection rules
- Established a clean baseline
- Exposed the honeypot to real internet traffic
- Detected malicious authentication activity
- Investigated endpoint activity
- Investigated database activity
- Performed KQL threat hunting
- Correlated multiple security data sources
- Reconstructed the incident timeline
- Contained the compromised system
- Compared pre-breach and post-breach artifacts
- Developed an eradication and recovery strategy
- Produced an incident response report

The project helped bridge the gap between cybersecurity theory and practical security operations.

---

# ⚠️ Security Notice

This project was conducted inside an isolated cybersecurity training environment using intentionally vulnerable systems and simulated corporate data.

No production systems, customer information, or confidential organizational data were used.

All credentials, identifiers, sensitive environment information, and other potentially sensitive artifacts should be removed or sanitized before publication.

The techniques demonstrated in this repository are intended strictly for cybersecurity education, defensive security research, threat detection, and incident response training.

---

# 👤 Author

**Sammy Tetzba**

Cybersecurity | Security Operations | Incident Response | Threat Detection

### Certifications

- CompTIA Security+
- Microsoft Azure Fundamentals (AZ-900)

### Areas of Interest

- Security Operations
- Incident Response
- Threat Hunting
- Detection Engineering
- Microsoft Sentinel
- Microsoft Defender
- Cloud Security
- Governance, Risk, and Compliance

---

# 🔗 Connect

**LinkedIn:**  
`https://www.linkedin.com/in/YOUR-PROFILE`

**GitHub:**  
`https://github.com/YOUR-USERNAME`

---

# ⭐ Project Status

```text
Status: Completed
Environment: Microsoft Azure
Project Type: Cybersecurity Home Lab / Cyber Range
Focus: Incident Response, SIEM, Threat Hunting, DFIR
```

---

> **Note:** Screenshots, reports, KQL queries, and sanitized log samples will be added to this repository as supporting evidence of the investigation.
