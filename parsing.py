import csv
from collections import Counter
from typing import Dict, List, Tuple
import re

def parse_log_line(line: str) -> Dict:
    pattern = r'(\d+\.\d+\.\d+\.\d+).*?"(\w+)\s+([^\s]+).*?"\s+(\d+)' #regrex that will used for extract the data
    match = re.search(pattern, line)
    if match:
        return {
            'ip': match.group(1),
            'method': match.group(2),
            'endpoint': match.group(3),
            'status': int(match.group(4))
        }
    return None

def count_requests_per_ip(log_entries: List[Dict]) -> List[Tuple[str, int]]:
    ip_counts = Counter(entry['ip'] for entry in log_entries if entry)
    return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

def find_most_accessed_endpoint(log_entries: List[Dict]) -> Tuple[str, int]:
    endpoint_counts = Counter(entry['endpoint'] for entry in log_entries if entry)
    return max(endpoint_counts.items(), key=lambda x: x[1])

def detect_suspicious_activity(log_entries: List[Dict], threshold: int = 3) -> List[Tuple[str, int]]:
    failed_logins = Counter()
    for entry in log_entries:
        if entry and entry['status'] == 401:
            failed_logins[entry['ip']] += 1
    
    suspicious = [(ip, count) for ip, count in failed_logins.items() if count >= threshold]
    return sorted(suspicious, key=lambda x: x[1], reverse=True)

def save_results_to_csv(requests_per_ip: List[Tuple], most_accessed: Tuple, suspicious: List[Tuple]):
    with open('log_analysis_results.csv', 'w', newline='') as f:
        writer = csv.writer(f)

        writer.writerow(['=== Requests per IP ==='])
        writer.writerow(['IP Address', 'Request Count'])
        writer.writerows(requests_per_ip)

        writer.writerow([])
        writer.writerow(['=== Most Accessed Endpoint ==='])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow(most_accessed)

        writer.writerow([])
        writer.writerow(['=== Suspicious Activity ==='])
        writer.writerow(['IP Address', 'Failed Login Count'])
        writer.writerows(suspicious)

def analyze_log_file(filename: str):

    with open(filename, 'r') as f:
        log_lines = f.readlines()
    
    log_entries = [parse_log_line(line) for line in log_lines]

    requests_per_ip = count_requests_per_ip(log_entries)
    most_accessed = find_most_accessed_endpoint(log_entries)
    suspicious_activity = detect_suspicious_activity(log_entries)

    print("\nRequests per IP Address:")
    print("IP Address           Request Count")
    print("-" * 40)

    for ip, count in requests_per_ip:
        print(f"{ip:<20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    print("-" * 40)
    for ip, count in suspicious_activity:
        print(f"{ip:<20} {count}")

    save_results_to_csv(requests_per_ip, most_accessed, suspicious_activity)
    print("\nResults have been saved to 'log_analysis_results.csv'")

if __name__ == "__main__":
    analyze_log_file("sample.csv")