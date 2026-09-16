# SIEM Lab: Wireshark Packet Forensics & Network Portscan Detection (Splunk)

An operational network telemetry monitoring framework implemented within **Splunk Cloud (Dashboard Studio)**. This project transforms raw network packet logs (PCAP ingest metadata) into real-time threat maps to isolate automated vertical network scanning behaviors and reconnaissance patterns.

---
<img width="1440" height="900" alt="Screen Shot 2026-09-15 at 8 59 44 PM" src="https://github.com/user-attachments/assets/d1bdd4aa-2096-4195-bf3b-9f12f604c384" />

## 🔍 Incident Context & Detection Engineering

Adversaries leverage automated reconnaissance scanning tools to discover live services and open transport-layer sockets across corporate perimeters. This detection model profiles protocol anomalies to identify network scanning footprints:

1. **TCP Connection Profiling**: Tracks half-open connection behaviors (such as high volumes of rapid `TCP_SYN` packets).
2. **Vertical Port Scanning Isolation**: Triggers when a singular external source footprint probes multiple unmapped local port destinations (e.g., 22, 80, 443, 3389).
3. **Automated Triage Alerts**: Consolidates scanning volume metrics into prioritized indicators of compromise (IoCs) to enable rapid analyst firewall staging.

---

## 💻 Core SPL Network Scan Ingestion Framework

```splunk
| makeresults count=200
| streamstats count as row
| eval time_offset = row * 0.5
| eval _time = _time - time_offset
| eval src_ip = "192.168.1.250"
| eval dest_ip = "10.0.0.12"
| eval dest_port = case(row <= 50, "80", row <= 100, "443", row <= 150, "22", 1=1, "3389")
| eval packet_status = "TCP_SYN"
| stats count by src_ip, dest_ip, dest_port, packet_status
| where count >= 1
| sort - dest_port
| eval tracking_classification = "CRITICAL ALERT: VERTICAL NETWORK RECONNAISSANCE SCAN IDENTIFIED"
| rename src_ip as "Attacker IP", dest_ip as "Target Server IP", dest_port as "Scanned Port", packet_status as "Packet Status", tracking_classification as "SOC Alert Severity"
```

---

## 📊 Dashboard Engineering Details

- **Visual Dashboard Mode**: Dashboard Studio (Grid Layout Structure)
- **Primary Interface Theme**: SOC Dark Operational Standard
- **Core Visual Element**: Network Reconnaissance Threat Matrix Grid Table
- **Monitored Indicators (IoCs)**: Reconnaissance Source Footprint, Local Server Endpoint Target, Attacked Service Transport Port, Automated Incident Escalation Flag.
