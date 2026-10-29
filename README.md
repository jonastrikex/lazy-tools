# 🛠️ Recon & Enumeration Toolkit

A personal collection of custom scripts and automation tools designed to streamline daily reconnaissance, system enumeration, and security auditing tasks.

---

## 🎯 Overview

This repository serves as a modular toolkit for ethical hacking and pentesting workflows. As new challenges and requirements arise during assessments, additional scripts will be added to automate repetitive tasks and speed up data gathering.

---

## ⚙️ Included Tools

### 🔍 Network & DNS Enumeration
* **`autoscan.py`**: Automated Nmap scanning wrapper for quick target identification and port enumeration.
* **`autodns.py`**: DNS discovery tool for querying records, zone transfers, and domain enumeration.

### 🛡️ System & Host Auditing
* **`autosockets.sh`**: Shell script to inspect active system sockets, listening ports, and establish an overview of local network activity to spot anomalies.

---

## 🚀 Getting Started

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/jonastrikex/](https://github.com/jonastrikex/)<REPO_NAME>.git
   cd <REPO_NAME>
   ```

2. **Make bash scripts executable:**
   ```bash
   chmod +x *.sh
   ```

3. **Prerequisites:**
   Ensure you have Python 3 and basic networking tools installed (`nmap`, `netstat`/`ss`, etc.).

---

## ⚠️ Disclaimer

*This toolkit is developed exclusively for educational purposes, personal laboratory testing, and authorized penetration testing. The user is solely responsible for compliance with all applicable local, state, and federal laws.*
