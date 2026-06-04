import os
from main import app, sanitise_path, remediate_path, scan_shell_configs, remediate_guidance

def test_sanitise_path_basic():
    # 1. Test removal of "." and duplicate entries while preserving order
    path = ".:/usr/bin:/bin:/usr/bin:/snap/bin:/snap/bin"
    sanitized, actions = sanitise_path(path)
    
    # Assert dot is removed and duplicates are removed while keeping first occurrence
    assert sanitized == "/usr/bin:/bin:/snap/bin"
    
    # Assert action log details
    criticals = [a for a in actions if a["reason"] == "critical"]
    duplicates = [a for a in actions if a["reason"] == "duplicate"]
    
    assert len(criticals) == 1
    assert criticals[0]["entry"] == "."
    
    assert len(duplicates) == 2
    assert duplicates[0]["entry"] == "/usr/bin"
    assert duplicates[1]["entry"] == "/snap/bin"

def test_sanitise_path_empty_and_separators():
    # 2. Test malformed inputs and empty separators (repeated colons ::)
    path = "/usr/bin::/bin:.:"
    sanitized, actions = sanitise_path(path)
    assert sanitized == "/usr/bin:/bin"
    
    criticals = [a for a in actions if a["reason"] == "critical"]
    # empty entries and dot should be criticals
    assert len(criticals) == 3  # empty string after first colon, dot, and empty string at end

def test_remediate_endpoint():
    # 3. Test remediate_path function directly
    test_path = ".:/usr/bin:/bin:/usr/bin"
    with open("/tmp/ghostpath_env.txt", "w") as f:
        f.write(test_path)
        
    data = remediate_path()
    assert "original_path" in data
    assert "sanitized_path" in data
    assert "actions" in data
    assert "diff" in data
    assert "risk_score" in data
    assert "issues" in data
    
    assert data["sanitized_path"] == "/usr/bin:/bin"
    
    # Check that it actually wrote it to /tmp/ghostpath_env.txt
    with open("/tmp/ghostpath_env.txt", "r") as f:
        saved_path = f.read().strip()
    assert saved_path == "/usr/bin:/bin"

def test_scan_shell_configs_real():
    # 4. Test live scanning of real .bashrc configuration
    findings = scan_shell_configs()
    
    # We know that ~/.bashrc exists and contains export PATH=.:$PATH on line 120
    bashrc_findings = [f for f in findings if f["file"] == "~/.bashrc"]
    assert len(bashrc_findings) >= 1
    
    dot_finding = [f for f in bashrc_findings if ".:" in f["content"]][0]
    assert dot_finding["issue_type"] == "critical"
    assert dot_finding["line_number"] == 120
    assert dot_finding["content"] == "export PATH=.:$PATH"
    assert "sed -i" in dot_finding["command"]
    assert "~/.bashrc" in dot_finding["command"]

def test_remediate_guidance_endpoint():
    # 5. Test the remediate_guidance endpoint
    res = remediate_guidance()
    assert "findings" in res
    assert isinstance(res["findings"], list)
    assert len(res["findings"]) >= 1
