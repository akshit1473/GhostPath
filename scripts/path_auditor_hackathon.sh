#!/usr/bin/bash

declare -a issues

collect_path_issues() {

    AUDIT_PATH="${TARGET_PATH:-$PATH}"

    IFS=':' read -ra PATH_DIRS <<< "$AUDIT_PATH"

    seen_dirs=()

    for dir in "${PATH_DIRS[@]}"; do

        # Empty entry
        if [ -z "$dir" ]; then
            issues+=("CRITICAL: empty PATH entry - Exploitability: An empty entry resolves to the current working directory. If a user runs a command in an untrusted directory (like /tmp), any binary placed there with that command's name executes immediately.")
            continue

        # Current directory
        elif [ "$dir" = "." ]; then
            issues+=("CRITICAL: '.' in PATH allows command hijacking - Exploitability: Prioritizing the current directory '.' directly in the PATH search order allows command hijacking. Running common utilities inside user-writable directories executes local untrusted scripts first.")
            continue

        # Non-existent directory
        elif [ ! -d "$dir" ]; then
            issues+=("INFO: $dir does not exist - Exploitability: Non-existent directory. Does not pose an active execution hijacking threat unless created by an attacker.")

        else

            norm_dir="$(realpath -m "$dir" 2>/dev/null || echo "$dir")"

            perm=$(stat -c "%A" "$dir" 2>/dev/null)

# Ignore virtualenvs
if [[ "$norm_dir" == *"/venv/"* || "$norm_dir" == *"/.venv/"* ]]; then

    if [ -w "$dir" ]; then
        issues+=("INFO: $dir is writable (expected virtualenv behavior) - Exploitability: Writable virtualenv directory is standard behavior for active Python environments but should be monitored to ensure untrusted users cannot write to it.")
    fi

else

    # true world writable detection
    if [[ "$perm" =~ ..w$ ]]; then
        issues+=("HIGH: $dir is world writable - Exploitability: Any local user or low-privilege process can write malicious binaries into this directory, which will be executed automatically.")
    fi

fi
        # Duplicate detection
        if [[ " ${seen_dirs[*]} " =~ " $dir " ]]; then
            issues+=("LOW: duplicate PATH entry $dir - Exploitability: Duplicate entries increase command resolution latency and complicate path resolution, but don't present direct shell execution hijack risk.")
        else
            seen_dirs+=("$dir")
        fi
    fi
    done
}

output_path_json() {

    status="ok"

    for i in "${issues[@]}"; do

        if [[ $i == CRITICAL* ]]; then
            status="critical"

        elif [[ $i == HIGH* && $status != "critical" ]]; then
            status="high"

        elif [[ $i == WARN* && $status != "critical" && $status != "high" ]]; then
            status="warn"

        elif [[ $i == MEDIUM* && $status != "critical" && $status != "high" && $status != "warn" ]]; then
            status="medium"
            
        elif [[ $i == LOW* && $status != "critical" && $status != "high" && $status != "warn" && $status != "medium" ]]; then
            status="low"
        fi

    done

    echo "{"
    echo "\"script\": \"path_auditor\","
    echo "\"data\": {"
    echo "\"status\": \"$status\","
    echo "\"issues\": ["

    for ((j=0; j<${#issues[@]}; j++)); do

        safe_issue=${issues[j]//\"/\\\"}

        printf "\"%s\"" "$safe_issue"

        if [ $j -lt $((${#issues[@]} - 1)) ]; then
            printf ",\n"
        fi

    done

    echo "]"
    echo "}"
    echo "}"
}

collect_path_issues

if [ "$1" == "--json" ]; then
    output_path_json

else

    echo "PATH AUDIT RESULT"

    if [ ${#issues[@]} -eq 0 ]; then
        echo "No issues detected"

    else

        for i in "${issues[@]}"; do
            echo "$i"
        done

    fi

fi
