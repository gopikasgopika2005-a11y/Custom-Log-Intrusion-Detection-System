
import re
import csv
from datetime import datetime, timedelta
from collections import defaultdict
import sqlite3
LOG_FILE = "sample_logs.txt"
ALERT_FILE = "alerts.csv"

THRESHOLD = 5
TIME_WINDOW_MINUTES = 5

def save_alerts_to_database(alerts):
    connection = sqlite3.connect("ids.db")

    try:
        cursor = connection.cursor()

        cursor.executemany("""
            INSERT INTO alerts (
                source_ip,
                failed_attempts,
                window_start,
                window_end,
                severity,
                alert_message
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, alerts)

        connection.commit()
        print("Alerts saved to SQLite database.")

    finally:
        connection.close()

def analyze_logs():
    failed_attempts = defaultdict(list)
    total_events = 0

    # Read and analyze log entries
    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            total_events += 1

            match = re.search(
                r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*"
                r"Failed login from "
                r"(\d{1,3}(?:\.\d{1,3}){3})",
                line
            )

            if match:
                timestamp_text = match.group(1)
                ip = match.group(2)

                timestamp = datetime.strptime(
                    timestamp_text, "%Y-%m-%d %H:%M:%S"
                )

                failed_attempts[ip].append(timestamp)

    alerts = []

    # Check each IP for repeated failures within 5 minutes
    for ip, timestamps in failed_attempts.items():
        timestamps.sort()

        left = 0

        for right in range(len(timestamps)):
            while (
                timestamps[right] - timestamps[left]
                > timedelta(minutes=TIME_WINDOW_MINUTES)
            ):
                left += 1

            count = right - left + 1

            if count >= THRESHOLD:
                alerts.append([
                    ip,
                    count,
                    timestamps[left].strftime("%Y-%m-%d %H:%M:%S"),
                    timestamps[right].strftime("%Y-%m-%d %H:%M:%S"),
                    "HIGH",
                    "Possible brute-force attempt within 5 minutes"
                ])
                break

    # Save the results
    with open(
        ALERT_FILE, "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.writer(file)
        writer.writerow([
            "Source IP",
            "Failed Attempts In Window",
            "Window Start",
            "Window End",
            "Severity",
            "Alert"
        ])
        writer.writerows(alerts)
        save_alerts_to_database(alerts)
    print("\nCUSTOM LOG IDS - TIME-BASED DETECTION")
    print("-" * 45)
    print("Total log events:", total_events)
    print("Unique IPs with failed logins:", len(failed_attempts))

    if alerts:
        print("\nSuspicious activity detected:")

        for alert in alerts:
            print("IP address:", alert[0])
            print("Failed attempts in window:", alert[1])
            print("Severity:", alert[4])
            print("Alert:", alert[5])
    else:
        print("\nNo time-based brute-force alerts detected.")

    print("\nReport saved to:", ALERT_FILE)


if __name__ == "__main__":
    analyze_logs()
