# 🕵️‍♂️ Wireshark for Network Intrusion Detection

This repository contains hands-on analysis of real-world malware network traffic using **Wireshark**, with a focus on **Agent Tesla** data exfiltration over **FTP** and **SMTP** protocols. The goal is to practice detecting intrusions, analyzing IOCs, and documenting malicious behavior observed in packet captures.

> 🔐 All PCAP files were obtained from [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/)  


---
## 📘 Case Studies

### 📦 1. AgentTesla Data Exfiltration via FTP

- Infected host uploads stolen credential log via unencrypted FTP
- `STOR` command used to transfer file: `PW_david.miller_2025_...html`
- Hardcoded credentials observed in packet stream

📄 Read the full report:   
[`AgentTesla-FTP-Intrusion-Report.md`](https://github.com/Zhydee/Wireshark-for-Network-Intrusion-detection/blob/main/AgentTesla-FTP-Intrusion-Report.md)  
[`AgentTesla-SMTP-Intrusion-Report.md`](https://github.com/Zhydee/Wireshark-for-Network-Intrusion-detection/blob/main/AgentTesla-SMTP-Intrusion-Report.md)

---

### 📧 2. AgentTesla Data Exfiltration via SMTP

- Base64-encoded credentials captured in `AUTH LOGIN`
- Email exfiltrates host info, public IP, and saved browser passwords
- Subject: `VIP Recovery`  
- Body includes stolen credentials and system metadata

📄 Read the full report:  
[`AgentTesla-SMTP-Intrusion-Report.md`](reports/AgentTesla-SMTP-Intrusion-Report.md)

---

## 🎯 Skills Demonstrated

- Wireshark filtering and stream analysis
- Detection of IOCs (Indicators of Compromise)
- Base64 decoding and MIME header interpretation
- Documentation of malware behavior in network traffic
- Cybersecurity incident response reporting

---

## 🧑‍💻 Author

Zaidi Fahmi Bin Zainudin  
Cybersecurity Student | SOC Analyst Aspirant

📬 [LinkedIn](https://www.linkedin.com/) (replace with your profile)  
📁 Part of my GitHub Cybersecurity Portfolio

---

## 📚 References

- [Agent Tesla - MITRE ATT&CK](https://attack.mitre.org/software/S0331/)
- [Wireshark User Guide](https://www.wireshark.org/docs/)
- [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/)

---
