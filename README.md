# 🕵️‍♂️ Phishing Email Analyzer

A SOC-oriented Python tool for analyzing phishing emails in `.eml` format.  
It extracts **headers, originating IPs, domains, URLs**, and performs **GeoIP lookups** to help identify Indicators of Compromise (IoCs).

---

## 📌 Features
- Parse `.eml` phishing emails
- Extract:
  - Sender details
  - Email subject & date
  - All IP addresses in headers
  - Domains & URLs in body
- GeoIP lookup (local DB or API)
- Save results to CSV for SOC workflows

---

## 🛠 Installation

**On Kali Linux:**
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-pip unzip git -y
pip3 install geoip2
