import os
import re
import json
import time
import logging
import datetime
import ipaddress
from collections import defaultdict, Counter
import threading
import queue
import matplotlib.pyplot as plt
import pandas as pd
from concurrent.futures import ThreadPoolExecutor

class LogAnalyzer:
    def __init__(self, config_file=None):
        """Initialize the log analyzer with optional configuration file."""
        # Default configuration
        self.config = {
            "log_directories": [],
            "log_patterns": {
                "apache": r'(\d+\.\d+\.\d+\.\d+).*?\[(.+?)\] "(\w+) (.+?) HTTP.*?" (\d+) .*',
                "ssh": r'(\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd.*: (.*?) from (\d+\.\d+\.\d+\.\d+)',
                "windows": r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*EventID=(\d+).*',
                "generic": r'.*'
            },
            "alert_rules": {
                "failed_login_threshold": 5,
                "suspicious_ip_ranges": ["192.168.1.0/24"],
                "critical_events": [4625, 4720, 1102]
            },
            "blacklisted_ips": [],
            "whitelist": {
                "ips": [],
                "users": []
            },
            "retention_days": 90,
            "output_directory": "./output"
        }
        
        # Load configuration if provided
        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                self.config.update(user_config)
        
        # Set up logging
        self.setup_logging()
        
        # Initialize data structures
        self.parsed_logs = []
        self.alerts = []
        self.statistics = {
            "total_logs": 0,
            "logs_by_source": Counter(),
            "logs_by_type": Counter(),
            "unique_ips": set(),
            "unique_users": set(),
            "error_counts": Counter()
        }
        
        # Thread-safe queues for log processing
        self.log_queue = queue.Queue()
        self.alert_queue = queue.Queue()
        
        # Event to signal threads to stop
        self.stop_event = threading.Event()
        
        self.logger.info("Log Analyzer initialized")

    def setup_logging(self):
        """Set up logging for the analyzer itself."""
        if not os.path.exists(self.config["output_directory"]):
            os.makedirs(self.config["output_directory"])
            
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f"{self.config['output_directory']}/analyzer.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("LogAnalyzer")

    def collect_logs(self, directory=None, file_pattern="*.log"):
        """Collect logs from the specified directory or configured directories."""
        import glob
        
        if directory:
            directories = [directory]
        else:
            directories = self.config["log_directories"]
        
        collected_files = []
        for directory in directories:
            if os.path.exists(directory):
                pattern = os.path.join(directory, file_pattern)
                files = glob.glob(pattern)
                collected_files.extend(files)
                self.logger.info(f"Collected {len(files)} log files from {directory}")
            else:
                self.logger.warning(f"Directory does not exist: {directory}")
        
        return collected_files

    def detect_log_type(self, log_line):
        """Detect the type of log based on its format."""
        for log_type, pattern in self.config["log_patterns"].items():
            if re.match(pattern, log_line):
                return log_type
        return "unknown"

    def parse_log_line(self, log_line, source_file):
        """Parse a log line based on its detected type."""
        log_type = self.detect_log_type(log_line)
        
        parsed_log = {
            "raw": log_line,
            "source": source_file,
            "type": log_type,
            "timestamp": datetime.datetime.now().isoformat(),
            "parsed": False
        }
        
        try:
            if log_type == "apache":
                pattern = self.config["log_patterns"]["apache"]
                match = re.match(pattern, log_line)
                if match:
                    ip, timestamp, method, path, status = match.groups()
                    parsed_log.update({
                        "parsed": True,
                        "ip": ip,
                        "timestamp": timestamp,
                        "method": method,
                        "path": path,
                        "status": int(status)
                    })
            
            elif log_type == "ssh":
                pattern = self.config["log_patterns"]["ssh"]
                match = re.match(pattern, log_line)
                if match:
                    timestamp, message, ip = match.groups()
                    parsed_log.update({
                        "parsed": True,
                        "timestamp": timestamp,
                        "message": message,
                        "ip": ip
                    })
                    
                    # Extract username if it's a login attempt
                    if "Failed password for" in message:
                        username = message.split("Failed password for")[1].split()[0]
                        parsed_log["username"] = username
                        parsed_log["event"] = "failed_login"
                    elif "Accepted password for" in message:
                        username = message.split("Accepted password for")[1].split()[0]
                        parsed_log["username"] = username
                        parsed_log["event"] = "successful_login"
            
            elif log_type == "windows":
                pattern = self.config["log_patterns"]["windows"]
                match = re.match(pattern, log_line)
                if match:
                    timestamp, event_id = match.groups()
                    parsed_log.update({
                        "parsed": True,
                        "timestamp": timestamp,
                        "event_id": int(event_id)
                    })
                    
                    # Check if it's a critical event
                    if int(event_id) in self.config["alert_rules"]["critical_events"]:
                        parsed_log["critical"] = True
        
        except Exception as e:
            self.logger.error(f"Error parsing log line: {e}")
            self.statistics["error_counts"]["parsing_errors"] += 1
        
        return parsed_log

    def process_log_file(self, file_path):
        """Process a single log file."""
        try:
            with open(file_path, 'r', errors='ignore') as f:
                for line in f:
                    if self.stop_event.is_set():
                        break
                    
                    if line.strip():
                        parsed_log = self.parse_log_line(line.strip(), file_path)
                        self.log_queue.put(parsed_log)
                        
            self.statistics["logs_by_source"][file_path] += 1
            return True
        except Exception as e:
            self.logger.error(f"Error processing log file {file_path}: {e}")
            self.statistics["error_counts"]["file_processing_errors"] += 1
            return False

    def log_processor_worker(self):
        """Worker function to process logs from the queue."""
        while not self.stop_event.is_set():
            try:
                parsed_log = self.log_queue.get(timeout=1)
                self.parsed_logs.append(parsed_log)
                
                self.statistics["total_logs"] += 1
                self.statistics["logs_by_type"][parsed_log["type"]] += 1
                
                if "ip" in parsed_log:
                    self.statistics["unique_ips"].add(parsed_log["ip"])
                
                if "username" in parsed_log:
                    self.statistics["unique_users"].add(parsed_log["username"])
                
                # Check for potential security issues
                self.analyze_log_entry(parsed_log)
                
                self.log_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in log processor: {e}")
                self.statistics["error_counts"]["processing_errors"] += 1

    def alert_processor_worker(self):
        """Worker function to process alerts from the queue."""
        while not self.stop_event.is_set():
            try:
                alert = self.alert_queue.get(timeout=1)
                self.alerts.append(alert)
                
                # Log the alert
                self.logger.warning(f"ALERT: {alert['message']} - {alert['details']}")
                
                # Here you would implement notification via email, SMS, etc.
                
                self.alert_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in alert processor: {e}")

    def analyze_log_entry(self, log_entry):
        """Analyze a single log entry for security issues."""
        # Check blacklisted IPs
        if "ip" in log_entry and log_entry["ip"] in self.config["blacklisted_ips"]:
            self.alert_queue.put({
                "timestamp": datetime.datetime.now().isoformat(),
                "type": "blacklisted_ip",
                "severity": "high",
                "message": f"Activity from blacklisted IP: {log_entry['ip']}",
                "details": log_entry
            })
        
        # Check suspicious IP ranges
        if "ip" in log_entry:
            ip = ipaddress.ip_address(log_entry["ip"])
            for suspicious_range in self.config["alert_rules"]["suspicious_ip_ranges"]:
                if ip in ipaddress.ip_network(suspicious_range):
                    self.alert_queue.put({
                        "timestamp": datetime.datetime.now().isoformat(),
                        "type": "suspicious_ip_range",
                        "severity": "medium",
                        "message": f"Activity from suspicious IP range: {log_entry['ip']}",
                        "details": log_entry
                    })
        
        # Check for failed logins
        if log_entry.get("event") == "failed_login" and "username" in log_entry:
            # In a real implementation, you would check against a persistent store
            # Here we're just creating an alert for demonstration
            self.alert_queue.put({
                "timestamp": datetime.datetime.now().isoformat(),
                "type": "failed_login",
                "severity": "medium",
                "message": f"Failed login for user: {log_entry['username']} from IP: {log_entry['ip']}",
                "details": log_entry
            })
        
        # Check for critical Windows events
        if log_entry.get("critical", False):
            self.alert_queue.put({
                "timestamp": datetime.datetime.now().isoformat(),
                "type": "critical_event",
                "severity": "high",
                "message": f"Critical event detected: {log_entry.get('event_id')}",
                "details": log_entry
            })

    def start_analysis(self, files=None):
        """Start the log analysis process."""
        if not files:
            files = self.collect_logs()
        
        if not files:
            self.logger.warning("No log files found to analyze")
            return False
        
        self.logger.info(f"Starting analysis of {len(files)} log files")
        
        # Start worker threads
        processor_thread = threading.Thread(target=self.log_processor_worker)
        processor_thread.daemon = True
        processor_thread.start()
        
        alert_thread = threading.Thread(target=self.alert_processor_worker)
        alert_thread.daemon = True
        alert_thread.start()
        
        # Process log files in parallel
        with ThreadPoolExecutor(max_workers=min(os.cpu_count(), 4)) as executor:
            executor.map(self.process_log_file, files)
        
        # Wait for all logs to be processed
        self.log_queue.join()
        self.alert_queue.join()
        
        # Stop worker threads
        self.stop_event.set()
        processor_thread.join(timeout=2)
        alert_thread.join(timeout=2)
        
        self.logger.info("Log analysis completed")
        return True

    def generate_statistics(self):
        """Generate statistics from the analyzed logs."""
        stats = {
            "total_logs": self.statistics["total_logs"],
            "total_alerts": len(self.alerts),
            "alerts_by_type": Counter(alert["type"] for alert in self.alerts),
            "alerts_by_severity": Counter(alert["severity"] for alert in self.alerts),
            "unique_ips": len(self.statistics["unique_ips"]),
            "unique_users": len(self.statistics["unique_users"]),
            "logs_by_type": dict(self.statistics["logs_by_type"]),
            "top_source_files": dict(self.statistics["logs_by_source"].most_common(5)),
            "error_counts": dict(self.statistics["error_counts"])
        }
        
        return stats

    def generate_visualizations(self, output_dir=None):
        """Generate visualizations from the analyzed data."""
        if not output_dir:
            output_dir = self.config["output_directory"]
            
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Prepare data for visualizations
        stats = self.generate_statistics()
        
        # Log type distribution
        plt.figure(figsize=(10, 6))
        plt.bar(stats["logs_by_type"].keys(), stats["logs_by_type"].values())
        plt.title("Log Distribution by Type")
        plt.xlabel("Log Type")
        plt.ylabel("Count")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(f"{output_dir}/log_distribution.png")
        
        # Alert severity distribution
        if stats["alerts_by_severity"]:
            plt.figure(figsize=(8, 8))
            labels = stats["alerts_by_severity"].keys()
            sizes = stats["alerts_by_severity"].values()
            plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
            plt.axis('equal')
            plt.title("Alerts by Severity")
            plt.tight_layout()
            plt.savefig(f"{output_dir}/alert_severity.png")
        
        self.logger.info(f"Visualizations saved to {output_dir}")
        
    def generate_report(self, output_file=None):
        """Generate a comprehensive report of the analysis."""
        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            output_file = f"{self.config['output_directory']}/report-{timestamp}.json"
        
        report = {
            "timestamp": datetime.datetime.now().isoformat(),
            "configuration": {k: v for k, v in self.config.items() if k != "blacklisted_ips"},
            "statistics": self.generate_statistics(),
            "alerts": self.alerts[:100]  # Limit the number of alerts in the report
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        self.logger.info(f"Report saved to {output_file}")
        return output_file

    def search_logs(self, query_params):
        """Search the parsed logs using the provided query parameters."""
        results = []
        
        for log in self.parsed_logs:
            match = True
            
            for key, value in query_params.items():
                if key not in log or log[key] != value:
                    match = False
                    break
            
            if match:
                results.append(log)
        
        return results

    def detect_anomalies(self, time_window=3600):
        """Detect anomalies in the log data within a specified time window (in seconds)."""
        # This is a simplified anomaly detection for demonstration
        # In a real implementation, you would use more sophisticated methods
        
        # Group logs by IP address
        logs_by_ip = defaultdict(list)
        for log in self.parsed_logs:
            if "ip" in log:
                logs_by_ip[log["ip"]].append(log)
        
        anomalies = []
        
        for ip, logs in logs_by_ip.items():
            # Skip whitelisted IPs
            if ip in self.config["whitelist"]["ips"]:
                continue
            
            # Check for high frequency of activity
            if len(logs) > 100:  # Arbitrary threshold
                anomalies.append({
                    "type": "high_activity",
                    "ip": ip,
                    "count": len(logs),
                    "message": f"Unusually high activity from IP: {ip}"
                })
            
            # Check for failed login attempts
            failed_logins = [log for log in logs if log.get("event") == "failed_login"]
            if len(failed_logins) >= self.config["alert_rules"]["failed_login_threshold"]:
                anomalies.append({
                    "type": "brute_force",
                    "ip": ip,
                    "count": len(failed_logins),
                    "message": f"Possible brute force attack from IP: {ip}"
                })
        
        return anomalies

    def correlation_analysis(self):
        """Perform correlation analysis to detect multi-stage attacks."""
        # This is a simplified correlation analysis for demonstration
        
        # Look for patterns indicating a potential attack chain
        suspicious_activities = []
        
        # Group activities by IP
        activities_by_ip = defaultdict(list)
        for log in self.parsed_logs:
            if "ip" in log:
                activities_by_ip[log["ip"]].append(log)
        
        for ip, activities in activities_by_ip.items():
            # Check for reconnaissance followed by exploitation pattern
            has_recon = False
            has_exploit = False
            
            for activity in activities:
                # Simplified detection of reconnaissance
                if activity.get("type") == "apache" and "scan" in activity.get("path", ""):
                    has_recon = True
                
                # Simplified detection of exploitation
                if activity.get("type") == "apache" and (
                    "exploit" in activity.get("path", "") or 
                    activity.get("status") == 500
                ):
                    has_exploit = True
            
            if has_recon and has_exploit:
                suspicious_activities.append({
                    "ip": ip,
                    "pattern": "recon_to_exploit",
                    "message": f"Possible attack chain detected from IP: {ip}"
                })
        
        return suspicious_activities

    def cleanup_old_logs(self):
        """Clean up logs older than the retention period."""
        retention_days = self.config["retention_days"]
        cutoff_date = datetime.datetime.now() - datetime.timedelta(days=retention_days)
        
        for directory in self.config["log_directories"]:
            if os.path.exists(directory):
                for filename in os.listdir(directory):
                    file_path = os.path.join(directory, filename)
                    if os.path.isfile(file_path):
                        file_modified = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
                        if file_modified < cutoff_date:
                            os.remove(file_path)
                            self.logger.info(f"Removed old log file: {file_path}")

    def run_interactive_analysis(self):
        """Run an interactive analysis session."""
        print("\n=== Log Analyzer Interactive Mode ===")
        print("1. Analyze log files")
        print("2. Search logs")
        print("3. Generate report")
        print("4. Generate visualizations")
        print("5. Show statistics")
        print("6. Detect anomalies")
        print("7. Correlation analysis")
        print("8. Exit")
        
        while True:
            choice = input("\nEnter your choice (1-8): ")
            
            if choice == "1":
                directory = input("Enter log directory (or press Enter for configured dirs): ")
                pattern = input("Enter file pattern (default: *.log): ") or "*.log"
                
                if directory:
                    files = self.collect_logs(directory, pattern)
                else:
                    files = self.collect_logs(file_pattern=pattern)
                
                if files:
                    print(f"Found {len(files)} log files.")
                    self.start_analysis(files)
                else:
                    print("No log files found.")
            
            elif choice == "2":
                if not self.parsed_logs:
                    print("No logs analyzed yet. Please analyze logs first.")
                    continue
                
                print("\nSearch logs:")
                print("Available fields: ip, type, event, username, status, critical")
                
                query = {}
                while True:
                    field = input("Enter field to search (or press Enter to execute): ")
                    if not field:
                        break
                    value = input(f"Enter value for {field}: ")
                    query[field] = value
                
                results = self.search_logs(query)
                print(f"\nFound {len(results)} matching logs.")
                for i, result in enumerate(results[:10]):
                    print(f"\n--- Result {i+1} ---")
                    for key, value in result.items():
                        if key != "raw":
                            print(f"{key}: {value}")
                
                if len(results) > 10:
                    print(f"\n... and {len(results) - 10} more results.")
            
            elif choice == "3":
                if not self.parsed_logs:
                    print("No logs analyzed yet. Please analyze logs first.")
                    continue
                
                output_file = input("Enter output file path (or press Enter for default): ")
                report_file = self.generate_report(output_file)
                print(f"Report generated: {report_file}")
            
            elif choice == "4":
                if not self.parsed_logs:
                    print("No logs analyzed yet. Please analyze logs first.")
                    continue
                
                output_dir = input("Enter output directory (or press Enter for default): ")
                self.generate_visualizations(output_dir)
                print("Visualizations generated.")
            
            elif choice == "5":
                if not self.parsed_logs:
                    print("No logs analyzed yet. Please analyze logs first.")
                    continue
                
                stats = self.generate_statistics()
                print("\n=== Analysis Statistics ===")
                print(f"Total logs analyzed: {stats['total_logs']}")
                print(f"Total alerts generated: {stats['total_alerts']}")
                print(f"Unique IP addresses: {stats['unique_ips']}")
                print(f"Unique usernames: {stats['unique_users']}")
                print("\nLog distribution by type:")
                for log_type, count in stats['logs_by_type'].items():
                    print(f"  {log_type}: {count}")
                
                print("\nAlerts by severity:")
                for severity, count in stats['alerts_by_severity'].items():
                    print(f"  {severity}: {count}")
            
            elif choice == "6":
                if not self.parsed_logs:
                    print("No logs analyzed yet. Please analyze logs first.")
                    continue
                
                window = input("Enter time window in seconds (default: 3600): ") or "3600"
                anomalies = self.detect_anomalies(int(window))
                
                print(f"\nDetected {len(anomalies)} anomalies:")
                for anomaly in anomalies:
                    print(f"- {anomaly['message']} (Count: {anomaly['count']})")
            
            elif choice == "7":
                if not self.parsed_logs:
                    print("No logs analyzed yet. Please analyze logs first.")
                    continue
                
                correlations = self.correlation_analysis()
                
                print(f"\nDetected {len(correlations)} potential attack patterns:")
                for corr in correlations:
                    print(f"- {corr['message']} (Pattern: {corr['pattern']})")
            
            elif choice == "8":
                print("Exiting interactive mode.")
                break
            
            else:
                print("Invalid choice. Please try again.")

# Example usage
if __name__ == "__main__":
    analyzer = LogAnalyzer()
    
    # Either run in interactive mode
    analyzer.run_interactive_analysis()
    
    # Or use programmatically
    """
    # Configure log directories
    analyzer.config["log_directories"] = ["/var/log", "/var/log/apache2"]
    
    # Start analysis
    analyzer.start_analysis()
    
    # Generate report
    analyzer.generate_report()
    
    # Generate visualizations
    analyzer.generate_visualizations()
    """