import os
from typing import List, Dict, Any

class LogIntelligence:
    def __init__(self):
        pass

    def parse_recent_logs(self) -> List[Dict[str, Any]]:
        """
        Parse system logs or shell history for suspicious activity.
        This is a stub implementation.
        """
        anomalies = []
        try:
            # Check bash history for suspicious commands if readable
            hist_file = os.path.expanduser("~/.bash_history")
            if os.path.exists(hist_file):
                with open(hist_file, "r", errors="ignore") as f:
                    lines = f.readlines()
                    # Check last 50 lines
                    for line in lines[-50:]:
                        line = line.strip()
                        if "chmod +x" in line and "./" in line:
                            anomalies.append({
                                "source": "bash_history",
                                "raw_log": line,
                                "reason": "Execution permission granted to local file",
                                "severity": "WARN"
                            })
                        elif "export PATH=.:" in line:
                            anomalies.append({
                                "source": "bash_history",
                                "raw_log": line,
                                "reason": "PATH hijack attempt in history",
                                "severity": "CRITICAL"
                            })
        except Exception:
            pass
            
        return anomalies
