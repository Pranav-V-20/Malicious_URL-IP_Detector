import requests
import json
import argparse
import time
import re
from pathlib import Path

VT_API_KEY = "5b3691f73c04d5f3430c7be2891ac23e06075eeaedc487b9724d9446fa27334b"  # Replace with your actual VirusTotal API key

# === VirusTotal Query === #
def check_virustotal(query, type_):
    url = f"https://www.virustotal.com/api/v3/{type_}s/{query}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        return malicious, suspicious
    else:
        return None, None

# === Log Parser === #
def extract_urls_ips(log_content):
    url_regex = re.compile(r'https?://[^\s]+')
    ip_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

    urls = url_regex.findall(log_content)
    ips = ip_regex.findall(log_content)

    return set(urls), set(ips)

# === Log Scanner === #
def scan_log_file(filepath):
    print(f"[+] Scanning {filepath}")
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    urls, ips = extract_urls_ips(content)

    for url in urls:
        print(f"\n🔗 Checking URL: {url}")
        malicious, suspicious = check_virustotal(url, "url")
        if malicious or suspicious:
            print(f"⚠️  Malicious: {malicious}, Suspicious: {suspicious}")
        else:
            print("✅ Clean")

    for ip in ips:
        print(f"\n🌐 Checking IP: {ip}")
        malicious, suspicious = check_virustotal(ip, "ip_address")
        if malicious or suspicious:
            print(f"⚠️  Malicious: {malicious}, Suspicious: {suspicious}")
        else:
            print("✅ Clean")

# === Real-time Monitoring === #
def watch_file(filepath, interval=30):
    print(f"[~] Watching {filepath} every {interval} seconds...")
    last_size = 0
    while True:
        size = Path(filepath).stat().st_size
        if size > last_size:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(last_size)
                new_data = f.read()
            urls, ips = extract_urls_ips(new_data)

            for url in urls:
                print(f"\n🔗 Checking new URL: {url}")
                malicious, suspicious = check_virustotal(url, "url")
                if malicious or suspicious:
                    print(f"⚠️  Malicious: {malicious}, Suspicious: {suspicious}")
                else:
                    print("✅ Clean")

            for ip in ips:
                print(f"\n🌐 Checking new IP: {ip}")
                malicious, suspicious = check_virustotal(ip, "ip_address")
                if malicious or suspicious:
                    print(f"⚠️  Malicious: {malicious}, Suspicious: {suspicious}")
                else:
                    print("✅ Clean")
            last_size = size
        time.sleep(interval)

# === Main CLI === #
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="🔍 Malicious URL/IP Detector using VirusTotal")
    parser.add_argument("file", help="Path to the log file to scan")
    parser.add_argument("--watch", action="store_true", help="Enable real-time monitoring of the file")
    parser.add_argument("--interval", type=int, default=30, help="Interval (seconds) for real-time scan")

    args = parser.parse_args()

    if not Path(args.file).exists():
        print("❌ Error: Log file does not exist.")
    else:
        if args.watch:
            watch_file(args.file, args.interval)
        else:
            scan_log_file(args.file)
