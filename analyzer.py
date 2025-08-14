import email
import re
import os
import tldextract
import subprocess
from colorama import Fore, Style
def extract_urls(text):
    url_pattern = r'(https?://[^\s]+)'
    return re.findall(url_pattern, text)

def is_suspicious_domain(domain):
    known_brands = ["paypal", "netflix", "microsoft", "google", "amazon"]
    for brand in known_brands:
        if brand in domain.lower() and domain.lower() != f"{brand}.com":
            return True
    return False

def get_origin_ip(received_headers):
    if not received_headers:
        return None
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    for header in received_headers:
        match = re.search(ip_pattern, header)
        if match:
            return match.group()
    return None

def geoip_lookup(ip):
    try:
        result = subprocess.run(["geoiplookup", ip], capture_output=True, text=True)
        return result.stdout.strip()
    except:
        return "GeoIP lookup failed."

def save_report(filename, report_text):
    report_path = os.path.join("reports", filename)
    with open(report_path, "w") as f:
        f.write(report_text)
    print(Fore.CYAN + f"[REPORT] Saved to {report_path}" + Style.RESET_ALL)
def analyze_email(file_path):
    with open(file_path, "rb") as f:
        msg = email.message_from_bytes(f.read())

    from_header = msg.get("From", "")
    subject = msg.get("Subject", "")
    return_path = msg.get("Return-Path", "")
    received = msg.get_all("Received", [])
    report = []
    report.append(f"File: {os.path.basename(file_path)}")
    report.append(f"From: {from_header}")
    report.append(f"Return-Path: {return_path}")
    report.append(f"Subject: {subject}")

    print(f"\n{Fore.CYAN}=== Analyzing: {os.path.basename(file_path)} ==={Style.RESET_ALL}")
    print(f"From: {from_header}")
    print(f"Return-Path: {return_path}")
    print(f"Subject: {subject}")

    origin_ip = get_origin_ip(received)
    if origin_ip:
        geo_info = geoip_lookup(origin_ip)
        print(Fore.YELLOW + f"[INFO] Origin IP: {origin_ip} → {geo_info}" + Style.RESET_ALL)
        report.append(f"Origin IP: {origin_ip}")
        report.append(f"GeoIP: {geo_info}")
    else:
        print(Fore.YELLOW + "[INFO] No origin IP found in headers." + Style.RESET_ALL)
        report.append("Origin IP: Not found")

    body_text = ""
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            try:
                body_text += part.get_payload(decode=True).decode(errors="ignore")
            except:
                pass

    urls = extract_urls(body_text)
    if not urls:
        print(Fore.GREEN + "[OK] No URLs found in email." + Style.RESET_ALL)
        report.append("URLs: None")
    else:
        print(Fore.YELLOW + f"[!] Found {len(urls)} URLs:" + Style.RESET_ALL)
        report.append("URLs Found:")
        for url in urls:
            domain_info = tldextract.extract(url)
            domain = f"{domain_info.domain}.{domain_info.suffix}"
            if is_suspicious_domain(domain):
                print(Fore.RED + f"  - {url}  [SUSPICIOUS DOMAIN]" + Style.RESET_ALL)
                report.append(f"  - {url}  [SUSPICIOUS DOMAIN]")
            elif url.startswith("http://"):
                print(Fore.RED + f"  - {url}  [NON-HTTPS LINK]" + Style.RESET_ALL)
                report.append(f"  - {url}  [NON-HTTPS LINK]")
            else:
                print(f"  - {url}")
                report.append(f"  - {url}")

    if from_header and return_path and from_header.split("@")[-1] != return_path.split("@")[-1]:
        print(Fore.RED + "[ALERT] Mismatch between From and Return-Path domains!" + Style.RESET_ALL)
        report.append("ALERT: Mismatch between From and Return-Path domains!")

    save_report(os.path.basename(file_path) + "_report.txt", "\n".join(report))

if __name__ == "__main__":
    sample_dir = "samples"
    for filename in os.listdir(sample_dir):
        if filename.endswith(".eml"):
            analyze_email(os.path.join(sample_dir, filename))
