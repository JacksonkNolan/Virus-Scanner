#!/bin/bash
cd "$(dirname "$0")"



# 1. CONFIGURATION
# ----------------
# Regex patterns to look for inside files
SIG_PATTERNS="malware|trojan|miner|base64_decode|eval\(|osascript -e|cmd\.exe|powershell|/bin/sh -i"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'


TEMP_DIR="/tmp/hyperscan_lite_extract"

# 2. THE SCAN ENGINE FUNCTION
# ---------------------------
run_scan() {
    TARGET="$1"
    
    if [ ! -e "$TARGET" ]; then
        echo -e "${RED}[!] Error: Target not found.${NC}"
        return
    fi

    echo ""
    echo -e " [.] Target: $TARGET"
    echo -e " [.] Engine: Recursive + Archive Support"
    echo -e " [.] Filters: Ignoring Unity/Library/Git/XML"
    echo " ------------------------------------------------"
    
    TOTAL_SCANNED=0
    THREATS_FOUND=0
    
    # Create/Clear report
    echo "Scan Report - $(date)" > scan_report.txt

    find "$TARGET" -type f -size -50M \
        ! -path "*/.git/*" \
        ! -path "*/Library/*" \
        ! -path "*/PackageCache/*" \
        ! -path "*/node_modules/*" \
        ! -name "*.xml" ! -name "*.json" ! -name "*.meta" ! -name "*.txt" \
        ! -name "*.png" ! -name "*.jpg" ! -name "*.mp4" ! -name "*.mp3" \
        2>/dev/null | while read -r file; do
        
        ((TOTAL_SCANNED++))
        IS_INFECTED=0
        THREAT_TYPE=""
        filename=$(basename "$file")
        extension="${filename##*.}"


        echo -ne "\r ${BLUE}Scanning:${NC} ...${filename:0:30}                               "

        if [[ "$extension" == "zip" ]]; then
            rm -rf "$TEMP_DIR"
            mkdir -p "$TEMP_DIR"
            unzip -q "$file" -d "$TEMP_DIR" 2>/dev/null
            
            if grep -rIEl "$SIG_PATTERNS" "$TEMP_DIR" > /dev/null; then
                IS_INFECTED=1
                THREAT_TYPE="Malware inside ZIP Archive"
            fi
            rm -rf "$TEMP_DIR"

        # --- STANDARD FILE SCANNING ---
        else
            if grep -IEl "$SIG_PATTERNS" "$file" > /dev/null; then
                IS_INFECTED=1
                THREAT_TYPE="Malicious Signature Found"
            fi
        fi

        # --- REPORTING ---
        if [ $IS_INFECTED -eq 1 ]; then
            echo -e "\n${RED}[!!!] THREAT DETECTED${NC}"
            echo -e "      File: $file"
            echo -e "      Type: $THREAT_TYPE"
            echo "THREAT: $file ($THREAT_TYPE)" >> scan_report.txt
            ((THREATS_FOUND++))
        fi

    done


    echo -e "\n\n════════════════════════════════════════════"
    echo " Files Analyzed: $TOTAL_SCANNED"
    
    REAL_THREAT_COUNT=$(grep -c "THREAT" scan_report.txt)
    
    if [ "$REAL_THREAT_COUNT" -gt 0 ]; then
        echo -e " Status: ${RED}$REAL_THREAT_COUNT THREATS DETECTED${NC}"
        echo -e " Check 'scan_report.txt' for details."
        open scan_report.txt
    else
        echo -e " Status: ${GREEN}SYSTEM CLEAN${NC}"
    fi
    echo "════════════════════════════════════════════"
}


# 3. THE INFINITE LOOP UI
# -----------------------
clear
echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     HYPERSCAN LITE v3.1 (Dev Edition)      ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"

while true; do
    echo ""
    echo -e "${YELLOW}Drag and drop folder to scan (or type 'q' to quit):${NC}"
    echo -n " > "
    read INPUT_DIR

    CLEAN_DIR=$(echo "$INPUT_DIR" | sed 's/\/$//' | sed 's/^"//' | sed 's/"$//')

    if [[ "$CLEAN_DIR" == "q" || "$CLEAN_DIR" == "exit" ]]; then
        echo "Exiting..."
        exit 0
    fi

    if [ -z "$CLEAN_DIR" ]; then
        echo -e "${RED}[!] Please drag a folder in.${NC}"
        continue
    fi

    run_scan "$CLEAN_DIR"
done
