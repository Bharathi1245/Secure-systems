import re
import sys
import json

def detect_threats(log_file, threshold):
    ip_counts = {}

    try:
        with open(log_file, 'r') as file:
            for line in file:
                line = line.strip()

                if re.search(r'failed\s+password', line, re.IGNORECASE):

                    # Extract IP addresses
                    ips = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', line)

                    for ip in ips:
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    except FileNotFoundError:
        print(f"Error: File '{log_file}' not found.")
        return
    except Exception as e:
        print(f"Unexpected error: {e}")
        return

    # Apply threshold
    malicious_ips = {
        ip: count for ip, count in ip_counts.items() if count >= threshold
    }

    print("DEBUG - IP Counts:", ip_counts)

    output_data = {
        "malicious_ips": [
            {"ip": ip, "attempts": count}
            for ip, count in malicious_ips.items()
        ]
    }

    with open("malicious_ips.json", "w") as json_file:
        json.dump(output_data, json_file, indent=4)

    print("Detection complete. Malicious IPs saved to malicious_ips.json")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python task2.py <log_file> <threshold>")
        sys.exit(1)

    log_file = sys.argv[1]

    try:
        threshold = int(sys.argv[2])
    except ValueError:
        print("Threshold must be an integer.")
        sys.exit(1)

    detect_threats(log_file, threshold)
