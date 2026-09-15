# SOC Lab: Network Reconnaissance & Port Scanning Detection (Splunk & Wireshark)

An advanced network security monitoring framework implemented within **Splunk Cloud (Dashboard Studio)**. This project maps analytical detection models to identify automated vertical and horizontal port scanning vectors using network packet metadata captures.

---

## 🔍 Incident Context & Threat Analysis

Before orchestrating a network intrusion, malicious entities execute reconnaissance tools (such as Nmap) to map active host targets and exposed application ports. This analytical pipeline correlates ingestion streams to flag reconnaissance footprinting:

1. **Connection Attempts Isolation**: Audits high-frequency transport layer validation requests (TCP SYN spikes) pointing to multiple non-responsive destinations.
2. **Volumetric Delta Thresholds**: Counts unique target ports probed by a single external source IP within a tight milliseconds timeframe.
3. **Proactive Remediation Escapes**: Escalates security flags to immediately block threat origins before active vulnerability exploitation occurs.

---

## 💻 Core SPL Portscan Detection Framework

```splunk
| makeresults count=200
| streamstats count as row
| eval time_offset = row * 0.1
| eval _time = _time - time_offset
| eval src_ip = "185.220.101.99"
| eval dest_ip = "192.168.1.10"
| eval probed_port = row + 100
| stats count as total_scanned_ports, values(probed_port) as scanned_port_list by src_ip, dest_ip
| where total_scanned_ports >= 50
| eval threat_indicator = "CRITICAL ALERT: HIGH-VOLUME VERTICAL PORT SCANNING ENGINES DETECTED"
| rename src_ip as "Attacker IP", dest_ip as "Internal Target Host", total_scanned_ports as "Probed Ports Count", scanned_port_list as "Sample Probed Ports", threat_indicator as "SOC Incident Priority"
```

---

## 📊 Dashboard Engineering Details

- **Visual Dashboard Mode**: Dashboard Studio (Grid Layout Architecture)
- **Primary Interface Theme**: SOC Dark Operational Standard
- **Core Visual Element**: Network Transport Security Ingestion Matrix
- **Monitored Indicators (IoCs)**: Attacker Recon Origin IP, Internal target victim, Automated scan volume count, Active list of exploited system ports.
