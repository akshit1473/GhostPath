# LOG PARSER 
# description => It takes a log file, filters by keyword, counts occurrences, and writes a summary

#!/usr/bin/bash 

LOGFILE="$1"

# ($1) takes input from the user, the above acts as the setup 

if [ -z "$LOGFILE" ]; then 
 	echo "[ERROR] No logfile provided"
	echo "usage: ./log_parser.sh <logfile>"
	exit 1

fi 
# above if condition checks if the logfile is present or not

if [ ! -f "$LOGFILE" ]; then

	echo "[ERROR] the file does not exist"
	exit 1
fi

# above if condition checks if the logfile exists or not


echo "================================"
echo "Log Analysis Report"
echo "File: $LOGFILE"
echo "================================"
echo ""

total_lines=$(wc -l < "$LOGFILE")
error_count=$(grep -ic "error" "$LOGFILE")
warning_count=$(grep -ic "warning" "$LOGFILE")


echo "Total lines: $total_lines"
echo "Error lines: $error_count"
echo "Warning lines: $warning_count"
echo ""

# general information gatherer

echo "[INFO] Unique Ips found: "
grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$LOGFILE" | sort -u

# explanation of the above command: -o prints the matched part, e=> extended regex , sort -u sorts all ips and -u removes duplicates.

echo ""

echo "[INFO] top Ips by frequency" 
grep -oE  '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$LOGFILE" | sort | uniq -c | sort -rn | head


echo "failed login attempts"
grep -i "failed" "$LOGFILE"



echo "=================================================="
echo "Analysis complete"
echo "=================================================="


# what the entire script is essentially doing - RAW LOG → EXTRACT → FILTER → COUNT → RANK → DISPLAY"
