def run_script(script, args=None, env=None):
    import subprocess, time, json, os
    from datetime import datetime

    start = time.time()

    cmd = ["bash", script]
    if args:
        cmd.extend(args)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env
    )

    duration = int((time.time() - start) * 1000)

    if result.returncode != 0:
        return {
            "execution": {
                "status": "error",
                "time_ms": duration
            },
            "meta": {
                "script": script,
                "timestamp": datetime.utcnow().isoformat()
            },
            "error": result.stderr
        }

    # ✅ THIS BLOCK MUST BE INDENTED INSIDE FUNCTION
    try:
        parsed = json.loads(result.stdout)

        return {
            "execution": {
                "status": "success",
                "time_ms": duration
            },
            "meta": {
                "script": script,
                "timestamp": datetime.utcnow().isoformat()
            },
            "data": parsed.get("data", parsed)
        }

    except Exception:
        return {
            "execution": {
                "status": "success",
                "time_ms": duration
            },
            "meta": {
                "script": script,
                "timestamp": datetime.utcnow().isoformat()
            },
            "output": result.stdout.strip()
        }
