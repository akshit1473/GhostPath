import subprocess
import json
from typing import List, Dict, Any

class ProcessMonitor:
    def __init__(self):
        pass

    def scan_processes(self) -> List[Dict[str, Any]]:
        """
        Scan running processes for anomalies.
        This is a stub implementation. In a real system, this would
        monitor /proc, use auditd, or continuously poll.
        """
        anomalies = []
        try:
            # We look for simple anomalies like 'python3' running from unusual paths
            # or processes with names like 'malicious_binary'
            cmd = ["ps", "aux"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]: # Skip header
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        user, pid, cpu, mem, vsz, rss, tty, stat, start, time, command = parts
                        
                        # Basic heuristics for demonstration
                        if "python3" in command and "./" in command:
                            anomalies.append({
                                "pid": pid,
                                "user": user,
                                "command": command,
                                "reason": "Suspicious execution path (./)",
                                "severity": "WARN"
                            })
                        elif "nc" in command or "netcat" in command:
                            anomalies.append({
                                "pid": pid,
                                "user": user,
                                "command": command,
                                "reason": "Network utility execution detected",
                                "severity": "LOW"
                            })
        except Exception as e:
            pass
            
        return anomalies
