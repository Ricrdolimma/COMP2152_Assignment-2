"""
Author: Ricardo Lima
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""
import socket
import threading
import sqlite3
import os
import platform
import datetime

print("Python version:", platform.python_version())
print("Operating system:", os.name)

common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner is reusing the code from NetworkTool by inheriting from it. 
# It already gets the target variable and its getter and setter, so it doesn’t need to create them again. 
# This way it avoids repeating the code and keep things organized
class NetworkTool():
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # It allows us to control how the target value is accessed and modified. 
    # We can keep it private and still use it safely from outside the class. 
    # It also helps prevent invalid values, like an empty string from being set.    
    @property
    def target(self):
        return self.__target
    
    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value
        
    def __del__(self):
        print("NetworkTool instance destroyed")

class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()
        
    def scan_port(self, port):
        sock = None
        #   Q4: What would happen without try-except here?
        # The program would crash if there is an error, like when the target machine is not reachable. 
        # It would stop running. Try-except prevents the program from breaking.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((self.target, port))

            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            service_name = common_ports.get(port, "Unknown")

            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")

        finally:
            if sock:
                sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]
    
    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading is used so multiple ports can be scanned at the same time instead of one by one. 
    # Which will make scanning much faster, especially when checking many ports. 
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )
        """)

        for port, status, service in results:
            cursor.execute("""
                INSERT INTO scans (target, port, status, service, scan_date)
                VALUES (?, ?, ?, ?, ?)
            """, (target, port, status, service, str(datetime.datetime.now())))

        conn.commit()
        conn.close()

    except sqlite3.Error as e:
        print(f"Database error: {e}")


def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("SELECT target, port, status, service, scan_date FROM scans")
        rows = cursor.fetchall()

        for target, port, status, service, scan_date in rows:
            print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")

        conn.close()

    except sqlite3.Error:
        print("No past scans found.")


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":

    target = input("Enter target IP (default 127.0.0.1): ")
    if target == "":
        target = "127.0.0.1"

    try:
        start_port = int(input("Enter start port (1-1024): "))
        if start_port < 1 or start_port > 1024:
            print("Port must be between 1 and 1024")
            exit()
    except ValueError:
        print("Invalid input. Please enter a valid integer")
        exit()

    try:
        end_port = int(input("Enter end port (1-1024): "))
        if end_port < 1 or end_port > 1024:
            print("Port must be between 1 and 1024")
            exit()
        if end_port < start_port:
            print("End port must be greater than or equal of start port")
            exit()
    except ValueError:
        print("Invalid input. Please enter a valid integer")
        exit()

    scanner = PortScanner(target)

    print(f"\nScanning {target} from port {start_port} to {end_port}...")

    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()

    print(f"\n--- Scan Results for {target} ---")
    for port, status, service in open_ports:
        print(f"Port {port}: {status} ({service})")

    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target, scanner.scan_results)

    choice = input("\nWould you like to see past scan history? (yes/no): ").lower()

    if choice == "yes":
        load_past_scans()
    

# Q5: New Feature Proposal
# I would add a feature that shows only open ports with known services like HTTP or SSH. 
# This makes the results easier to read by focusing on useful information. 
# I would use a list comprehension to filter scan_results and remove entries with "Unknown" services.

# Diagram: See diagram_studentID.png in the repository root
