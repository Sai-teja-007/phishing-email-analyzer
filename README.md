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
```

ownload MaxMind GeoLite2 database:
```
wget https://github.com/P3TERX/GeoLite.mmdb/raw/master/GeoLite2-City.mmdb -O GeoLite2-City.mmdb
```
📂 Usage

Place phishing emails in the samples/ folder (must be .eml format).

Run
```
python3 analyzer.py samples/
```

📌 Example Output
```
    Processing: invoice_notice.eml
    From: admin@fakebank.com
    Subject: Urgent: Account Verification
    Originating IP: 185.210.219.42
    Location: Russia (Moscow)
    URLs Found:
        - http://secure-fakebank-login.com
```
