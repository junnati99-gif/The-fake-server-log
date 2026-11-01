from collections import defaultdict

# Configuration: Flag any IP with 3 or more failed login attempts
FAILED_THRESHOLD = 3
LOG_FILE = "server_access.log"

def analyze_logs():
    # Dictionary to keep track of failed attempts per IP address
    failed_attempts = defaultdict(int)
    
    print("[*] Starting Blue Team Log Analysis...")
    
    try:
        with open(LOG_FILE, "r") as file:
            for line in file:
                # Check if the log line indicates a failed login
                if "Status: FAILED" in line:
                    # Extract the IP address from the line
                    # Splitting by "IP: " and taking the first part of the remaining string
                    parts = line.split("IP: ")
                    if len(parts) > 1:
                        ip = parts[1].split(" ")[0]
                        failed_attempts[ip] += 1
                        
        # Check if any IP exceeded our security threshold
        alerts_triggered = False
        for ip, count in failed_attempts.items():
            if count >= FAILED_THRESHOLD:
                print(f"\n[🚨 ALERT] Possible Brute Force Attack Detected!")
                print(f" -> Malicious IP: {ip}")
                print(f" -> Total Failed Attempts: {count}")
                print(f" -> Recommended Action: Block IP at firewall level immediately.")
                alerts_triggered = True
                
        if not alerts_triggered:
            print("[+] Scan complete. No malicious activity detected.")
            
    except FileNotFoundError:
        print(f"[Error] The file {LOG_FILE} was not found. Please create it first.")

if __name__ == "__main__":
    analyze_logs()
