#!/usr/bin/env python3
"""
MikroTik Security Monitor v1.2
Real-time failed login and brute force attack detection
"""

import routeros_api
import json
import pandas as pd
from datetime import datetime, timedelta
import os
import platform
import subprocess
import re
from collections import defaultdict
import warnings

# Configuration
CONFIG_FILE = "mikrotik_config.json"
LOG_CSV = "failed_logins_master.csv"
FAILURE_KEYWORDS = ["login failure", "failed", "denied", "invalid"]
BRUTE_FORCE_THRESHOLD = 2  # Attempts
BRUTE_FORCE_WINDOW = 5     # Minutes

warnings.filterwarnings("ignore", category=UserWarning)

def load_config():
    """Load MikroTik connection settings"""
    with open(CONFIG_FILE) as f:
        return json.load(f)

def connect_routeros(config):
    """Establish API connection"""
    return routeros_api.RouterOsApiPool(
        config["host"],
        username=config["username"],
        password=config["password"],
        port=config["port"],
        plaintext_login=True
    )

def extract_ip(message):
    """Extract IP address from log message"""
    match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', message)
    return match.group(0) if match else None

def open_file(filepath):
    """Open file in default application"""
    try:
        if platform.system() == "Windows":
            os.startfile(filepath)
        elif platform.system() == "Darwin":
            subprocess.call(["open", filepath])
        else:
            subprocess.call(["xdg-open", filepath])
    except Exception as e:
        print(f"[!] Could not open file: {e}")

def main():
    print("=== MikroTik Security Monitor ===")
    
    try:
        # Connect to RouterOS
        config = load_config()
        connection = connect_routeros(config)
        api = connection.get_api()
        
        # Fetch logs
        logs = api.get_resource('/log')
        log_entries = logs.get()
        print(f"[i] Retrieved {len(log_entries)} log entries")

        # Process logs
        failed_logins = []
        for entry in log_entries:
            message = entry.get("message", "").lower()
            if any(keyword in message for keyword in FAILURE_KEYWORDS):
                failed_logins.append({
                    "time": entry.get("time"),
                    "message": entry.get("message"),
                    "topics": entry.get("topics"),
                    "id": f"{entry.get('time')}|{entry.get('message')}"
                })

        # Save results
        df = pd.DataFrame(failed_logins)
        existing_df = pd.read_csv(LOG_CSV) if os.path.exists(LOG_CSV) else pd.DataFrame()
        new_entries = df[~df['id'].isin(existing_df.get('id', []))].copy()
        
        if not new_entries.empty:
            # Save to master CSV
            pd.concat([existing_df, new_entries]).to_csv(LOG_CSV, index=False)
            print(f"[+] Logged {len(new_entries)} new failed login(s)")
            
            # Save timestamped report
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
            report_file = f"failed_logins_{timestamp}.txt"
            with open(report_file, "w") as f:
                f.write("=== Failed Login Report ===\n")
                f.write(f"Generated: {datetime.now()}\n\n")
                new_entries.to_string(f, index=False)
            open_file(report_file)
            
            # Brute force detection
            new_entries['ip'] = new_entries['message'].apply(extract_ip)
            new_entries['datetime'] = pd.to_datetime(new_entries['time'], errors='coerce')
            
            ip_attempts = defaultdict(list)
            for _, row in new_entries.dropna().iterrows():
                ip_attempts[row['ip']].append(row['datetime'])
            
            brute_force_ips = [
                ip for ip, times in ip_attempts.items()
                if len(times) >= BRUTE_FORCE_THRESHOLD and
                (max(times) - min(times)) <= timedelta(minutes=BRUTE_FORCE_WINDOW)
            ]
            
            if brute_force_ips:
                alert_file = f"brute_force_alert_{timestamp}.txt"
                with open(alert_file, "w") as f:
                    f.write("=== BRUTE FORCE ALERT ===\n")
                    f.write(f"Time: {datetime.now()}\n")
                    f.write(f"Threshold: {BRUTE_FORCE_THRESHOLD} attempts in {BRUTE_FORCE_WINDOW} minutes\n\n")
                    f.write("Suspicious IPs:\n" + "\n".join(brute_force_ips))
                print(f"[!] Brute force detected from: {', '.join(brute_force_ips)}")
                open_file(alert_file)
        else:
            print("[*] No new failed logins found")

    except Exception as e:
        print(f"[!] Error: {str(e)}")
    finally:
        if 'connection' in locals():
            connection.disconnect()

if __name__ == "__main__":
    main()