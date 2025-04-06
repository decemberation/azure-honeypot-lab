# 🛡️ Azure Honeypot Project: Cloud-Based Threat Detection Lab

## 📖 Overview
This project simulates a **production-like honeypot** on Microsoft Azure that is open to the public internet to attract **brute-force attacks**. Using **Microsoft Sentinel** and **Log Analytics**, it enables live detection and geolocation of attack sources—perfect for SOC training, threat hunting, and real-world cyber defense practice.

---

## 🧱 Architecture Diagram

![Architecture](./images/architecture.png)

---

## ⚙️ Cloud Infrastructure

| Component                | Purpose                                      |
|--------------------------|----------------------------------------------|
| Azure VM                 | Runs Windows Server and acts as the honeypot |
| Network Security Group   | Add a custom inbound rule to intentionally expose the honeypot to the public internet    |
| Public IP                | Connects attackers to VM                     |
| Log Analytics Workspace  | Ingests Windows Event Logs                   |
| Microsoft Sentinel       | SIEM layer for alerting & dashboards         |
| GeoIP Watchlist          | CSV-based mapping of IPs to countries        |
| KQL Queries              | Powers data analysis and alert triggers      |

---

## 📊 KQL Example: 

**Detect failed logins with GeoIP**

```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, Computer, EventID, Activity, IpAddress
```

**Observe geographic information to see where the attacks are coming from**

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
```
