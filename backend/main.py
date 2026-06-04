from fastapi import FastAPI
from executor import run_script
from risk_engine import analyze_risk
from fastapi.responses import FileResponse
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)
parent_dir = os.path.dirname(BASE_DIR)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from engines.correlation_engine import CorrelationEngine
from monitors.log_parser import LogIntelligence
from monitors.process_parser import ProcessMonitor
from models.events import RuntimeEvent
from pydantic import BaseModel
from typing import Optional

PATH_AUDITOR_SCRIPT = os.path.join(
    BASE_DIR, "..", "scripts", "path_auditor_hackathon.sh"
)

PATH_ATTACK_SCRIPT = os.path.join(
    BASE_DIR, "..", "scripts", "path_hijack_hackathon.sh"
)

from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

correlation_engine = CorrelationEngine()
log_parser = LogIntelligence()
process_monitor = ProcessMonitor()

def get_live_env():
    live_env = os.environ.copy()
    try:
        with open("/tmp/ghostpath_env.txt", "r") as f:
            live_path = f.read().strip()
            if live_path:
                live_env["TARGET_PATH"] = live_path
    except Exception:
        pass
    return live_env

def sanitise_path(raw_path: str) -> tuple[str, list[dict]]:
    """Return cleaned PATH and a list of actions.
    Each action dict contains:
        entry: the directory removed or kept
        reason: "critical" | "duplicate" | "info"
    Order of remaining entries is preserved.
    """
    parts = raw_path.split(":")
    seen: set[str] = set()
    cleaned: list[str] = []
    actions: list[dict] = []
    for part in parts:
        # Critical entries: empty or '.'
        if part == "" or part == ".":
            actions.append({"entry": part or "(empty)", "reason": "critical"})
            continue
        # Duplicate detection – keep first occurrence
        if part in seen:
            actions.append({"entry": part, "reason": "duplicate"})
            continue
        # Keep legitimate directory
        seen.add(part)
        cleaned.append(part)
        actions.append({"entry": part, "reason": "info"})
    return ":".join(cleaned), actions

# -----------------------------------------------------------------
# POST endpoint for PATH remediation
@app.post("/api/remediate/path")
def remediate_path():
    """Sanitise the current live PATH and store it back to the temp file.
    Returns original PATH, sanitized PATH, a list of actions and a human-readable diff,
    along with updated risk_score and issues list.
    """
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("ghostpath")
    logger.info("POST /api/remediate/path - Starting PATH remediation")

    try:
        # 1️⃣ Read current live PATH
        live_env = get_live_env()
        current_path = live_env.get("TARGET_PATH") or live_env.get("PATH", "")
        logger.info(f"Original PATH: {current_path}")

        # 2️⃣ Sanitise the PATH
        sanitized_path, actions = sanitise_path(current_path)
        logger.info(f"Sanitized PATH: {sanitized_path}")
        logger.info(f"Actions taken: {actions}")

        # 3️⃣ Persist the sanitized PATH back to the temp file
        with open("/tmp/ghostpath_env.txt", "w") as f:
            f.write(sanitized_path)
        logger.info("Successfully persisted sanitized PATH to /tmp/ghostpath_env.txt")

        # 4️⃣ Build diff lines for UI display
        diff_lines: list[str] = []
        for act in actions:
            if act["reason"] == "critical":
                diff_lines.append(f"✖ Removed critical entry '{act['entry']}'")
            elif act["reason"] == "duplicate":
                diff_lines.append(f"✖ Removed duplicate '{act['entry']}'")
            else:
                diff_lines.append(f"ℹ Kept '{act['entry']}'")

        # 5️⃣ Perform a fresh inline audit to get updated risk score and issues list
        raw_audit = run_script(PATH_AUDITOR_SCRIPT, ["--json"], env=get_live_env())
        analysis = analyze_risk(raw_audit)
        logger.info(f"Post-remediation analysis: {analysis}")

        evt = RuntimeEvent.create(
            source="REMEDIATION_ENGINE",
            event_type="REMEDIATION_APPLIED",
            severity="RESOLVED",
            message=f"Sanitized PATH. Evaluated {len(actions)} entries.",
            data={"actions": actions, "sanitized_path": sanitized_path}
        )
        correlation_engine.process_event(evt)

        return {
            "original_path": current_path,
            "sanitized_path": sanitized_path,
            "actions": actions,
            "diff": diff_lines,
            "risk_score": analysis.get("risk_score", 0),
            "vulnerable": analysis.get("vulnerable", False),
            "issues": analysis.get("issues", [])
        }
    except Exception as e:
        logger.error(f"Remediation failed: {str(e)}", exc_info=True)
        return {
            "error": "remediation_failed",
            "message": str(e),
            "risk_score": 0,
            "vulnerable": False,
            "issues": []
        }


@app.get("/")
def serve_ui():
    return FileResponse("../frontend/index.html")


@app.get("/")
def root():
    return {"status": "working"}


def scan_shell_configs() -> list[dict]:
    """Scan shell configurations (~/.bashrc, ~/.profile, etc.) for persistent unsafe PATH configurations.
    Returns a list of persistent config risks.
    """
    import glob
    home = os.path.expanduser("~")
    targets = [
        os.path.join(home, ".bashrc"),
        os.path.join(home, ".zshrc"),
        os.path.join(home, ".profile"),
        os.path.join(home, ".bash_profile")
    ]
    
    findings = []
    for target in targets:
        if not os.path.isfile(target):
            continue
        try:
            with open(target, "r", errors="ignore") as f:
                for i, line in enumerate(f, 1):
                    clean_line = line.strip()
                    # Skip comments or empty lines
                    if not clean_line or clean_line.startswith("#"):
                        continue
                    # Look for PATH modifications
                    if "PATH=" in clean_line:
                        # Extract the assignment right side
                        if "=" in clean_line:
                            parts = clean_line.split("=", 1)
                            right_side = parts[1].strip()
                            
                            # Clean surrounding quotes
                            cleaned_right = right_side.replace('"', '').replace("'", "")
                            path_entries = cleaned_right.split(":")
                            
                            has_dot = False
                            has_empty = False
                            for entry in path_entries:
                                if entry == ".":
                                    has_dot = True
                                elif entry == "":
                                    has_empty = True
                            
                            if has_dot or has_empty:
                                recommended = clean_line
                                # Handle double colons
                                recommended = recommended.replace("::", ":")
                                # Handle prepended dot
                                recommended = recommended.replace(".:", "").replace("=.", "=")
                                # Handle appended dot
                                recommended = recommended.replace(":.", "")
                                
                                # Escape command for terminal safety
                                escaped_line = clean_line.replace('$', '\\$').replace('"', '\\"')
                                escaped_rec = recommended.replace('$', '\\$').replace('"', '\\"')
                                short_target = target.replace(home, "~")
                                
                                sed_cmd = f"sed -i 's#{escaped_line}#{escaped_rec}#g' {short_target}"
                                
                                findings.append({
                                    "file": short_target,
                                    "full_path": target,
                                    "line_number": i,
                                    "content": clean_line,
                                    "issue_type": "critical" if has_dot else "medium",
                                    "recommended_change": recommended,
                                    "why": "The entry '.' (current directory) allows command hijacking by prioritizing the current directory during search execution. If an attacker places a malicious script (like python3) in a directory you visit, running python3 will execute the malicious script instead of the standard binary.",
                                    "command": sed_cmd
                                })
        except Exception:
            pass
    return findings

@app.get("/api/remediate/guidance")
def remediate_guidance():
    """Returns granular persistent risk reports and copy-paste remediation instructions."""
    findings = scan_shell_configs()
    return {"findings": findings}

@app.get("/api/audit/path")
def audit_path():
    raw = run_script(PATH_AUDITOR_SCRIPT, ["--json"], env=get_live_env())
    analysis = analyze_risk(raw)
    
    # Enrich response with persistent configuration findings
    persistent_findings = scan_shell_configs()
    analysis["persistent_findings"] = persistent_findings
    analysis["has_persistent_risk"] = len(persistent_findings) > 0

    # Collect process & log intelligence
    proc_anomalies = process_monitor.scan_processes()
    log_anomalies = log_parser.parse_recent_logs()

    if analysis.get("vulnerable"):
        if not any(e.source == "PATH_AUDITOR" and e.severity == "CRITICAL" for e in correlation_engine.timeline.events):
            evt = RuntimeEvent.create(
                source="PATH_AUDITOR",
                event_type="CRITICAL_VULNERABILITY",
                severity="CRITICAL",
                message="Vulnerable PATH precedence detected during active audit.",
                data={"issues": analysis.get("issues", [])}
            )
            correlation_engine.process_event(evt)
    
    timeline_state = correlation_engine.correlate_environment(
        path_analysis=analysis,
        process_anomalies=proc_anomalies,
        log_anomalies=log_anomalies,
        persistent_findings=persistent_findings
    )

    analysis["threat_confidence"] = timeline_state.threat_confidence
    analysis["compromise_likelihood"] = timeline_state.compromise_likelihood
    analysis["severity_escalation"] = timeline_state.severity_escalation
    analysis["mitre_mappings"] = timeline_state.mitre_mappings
    analysis["correlated_incidents"] = timeline_state.correlated_incidents
    analysis["remediation_confidence"] = timeline_state.remediation_confidence
    analysis["active_narrative"] = timeline_state.active_narrative
    analysis["timeline_events"] = [e.dict() for e in timeline_state.events]
    analysis["multi_terminal_demo"] = timeline_state.multi_terminal_demo

    return analysis


@app.get("/api/simulate/attack")
def simulate_attack():
    audit = run_script(PATH_AUDITOR_SCRIPT, ["--json"], env=get_live_env())
    analysis = analyze_risk(audit)

    if not analysis.get("vulnerable"):
        return {
            "status": "blocked",
            "message": "No vulnerability detected",
            "analysis": analysis
        }

    exploit = run_script(PATH_ATTACK_SCRIPT)
    output_data = exploit.get("output") or exploit.get("data")

    evt = RuntimeEvent.create(
        source="ATTACK_SIMULATION",
        event_type="EXPLOIT_SIMULATED",
        severity="CRITICAL",
        message="Executed PATH hijack binary planting simulation.",
        data={"output": output_data}
    )
    correlation_engine.process_event(evt)

    return {
        "status": exploit["execution"]["status"],
        "output": output_data,
        "analysis": analysis
    }

@app.get("/api/summary")
def summary():
    raw = run_script("../scripts/path_auditor_hackathon.sh", env=get_live_env())

    if raw.get("execution", {}).get("status") != "success":
        return {"error": "Audit script failed", "details": raw}

    analysis = analyze_risk(raw)

    return {
        "overall_risk": "HIGH" if analysis.get("vulnerable") else "LOW",
        "risk_score": analysis.get("risk_score"),
        "vulnerable": analysis.get("vulnerable"),
        "issues": analysis.get("insights", [])
    }

class DemoStateUpdate(BaseModel):
    attacker_status: Optional[str] = None
    attacker_cmd: Optional[str] = None
    attacker_output: Optional[str] = None
    victim_status: Optional[str] = None
    victim_cmd: Optional[str] = None
    victim_output: Optional[str] = None

@app.post("/api/demo/multi-terminal")
def update_demo_terminal(req: DemoStateUpdate):
    demo = correlation_engine.timeline.multi_terminal_demo
    if req.attacker_status: demo["attacker_shell"]["status"] = req.attacker_status
    if req.attacker_cmd is not None: demo["attacker_shell"]["last_command"] = req.attacker_cmd
    if req.attacker_output is not None: demo["attacker_shell"]["output"] = req.attacker_output
    if req.victim_status: demo["victim_shell"]["status"] = req.victim_status
    if req.victim_cmd is not None: demo["victim_shell"]["last_command"] = req.victim_cmd
    if req.victim_output is not None: demo["victim_shell"]["output"] = req.victim_output
    return {"status": "success", "multi_terminal_demo": demo}

@app.get("/api/demo/replay")
def get_replay_stages():
    stages = [
        {
            "stage": 1,
            "title": "Stage 1: Vulnerability Reconnaissance",
            "description": "GhostPath identifies a relative directory '.' or world-writable folder in the active PATH precedence.",
            "telemetry": "PATH = .:/usr/bin:/bin",
            "mitre": "T1574.007 - PATH Environment Variable"
        },
        {
            "stage": 2,
            "title": "Stage 2: Adversary Binary Planting",
            "description": "Attacker plants a malicious executable named 'python3' into the vulnerable relative directory.",
            "telemetry": "echo '#!/bin/bash\\necho PYTHON EXECUTION HIJACKED' > ./python3 && chmod +x ./python3",
            "mitre": "T1059 - Command and Scripting Interpreter"
        },
        {
            "stage": 3,
            "title": "Stage 3: Victim Execution Interception",
            "description": "Victim executes 'python3'. The shell searches '.' first and triggers the malicious script instead of /usr/bin/python3.",
            "telemetry": "🔥 PYTHON EXECUTION HIJACKED",
            "mitre": "T1574.007 - Search Order Hijacking"
        },
        {
            "stage": 4,
            "title": "Stage 4: Automated Threat Correlation",
            "description": "GhostPath correlation engine fuses PATH vulnerability, process anomaly, and log history into a high-confidence compromise incident.",
            "telemetry": "Threat Confidence: 100% | Likelihood: CRITICAL",
            "mitre": "Heuristic Behavioral Fusion"
        },
        {
            "stage": 5,
            "title": "Stage 5: Surgical Runtime Remediation",
            "description": "GhostPath sanitizes the active runtime PATH and generates permanent sed guidance for persistent shell profiles.",
            "telemetry": "Sanitized PATH: /usr/bin:/bin | Status: SECURE",
            "mitre": "Automated Environment Restoration"
        }
    ]
    return {"stages": stages}
