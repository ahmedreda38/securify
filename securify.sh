#!/usr/bin/env bash

# ===============================================================
#  Securify – Unified SAST/DAST Automation Engine
#  Author: Ahmed Reda
#
#  Features:
#   - CLI + Config driven
#   - Advanced Semgrep SAST scanning
#   - Advanced Snyk vulnerability scanning
#   - Nikto full aggressive web vulnerability scanning
#   - Nmap NSE scripts + vuln detection
#   - Unified CSV reporting for all tools
#
#  Usage:
#    ./securify.sh --config-file securify.conf --repo-path ./myapp
# ===============================================================

CONFIG_FILE="securify.conf"
REPO_PATH="."



# ------------------------------
# Parse CLI Arguments
# ------------------------------
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --config-file|-c)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --repo-path|-r)
            REPO_PATH="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ------------------------------
# Validate inputs
# ------------------------------
if [[ -z "$CONFIG_FILE" ]]; then
    echo "[-] Error: Missing --config-file argument"
    exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[-] Error: Config file not found: $CONFIG_FILE"
    exit 1
fi

source "$CONFIG_FILE"

mkdir -p "$RESULTS_DIR"



if [[ -n "$REPO_PATH" ]]; then
    SOURCE_CODE_PATH="$REPO_PATH"
fi

if [[ -z "$SOURCE_CODE_PATH" ]]; then
    echo "[-] Error: source code path not provided (via CLI or config)."
    exit 1
fi

# Ensure CSV exists and reset it if already present
echo "Finding,Severity,Tool,Details" > "$OUTPUT_CSV"


###############################################################
#  CSV Writer
###############################################################
add_finding() {
    echo "\"$1\",\"$2\",\"$3\",\"$4\"" >> "$OUTPUT_CSV"
}


###############################################################
#  SEMGREP (Advanced SAST)
###############################################################
run_semgrep() {
    if [[ "$ENABLE_SEMGREP" != "true" ]]; then return; fi
    echo -e "[+] Running \033[31;47;1mSemgrep (advanced ruleset)\033[0m ..."

    $SEMGREP_CMD scan "$SOURCE_CODE_PATH" --json-output=$SEMGRP_OUT 2>/dev/null

    # Parse findings
   if [[ -f "$SEMGRP_OUT" ]]; then
        jq -c '.results[]' "$SEMGRP_OUT" 2>/dev/null | while read -r f; do
            rule_id=$(echo "$f" | jq -r '.check_id')
            severity=$(echo "$f" | jq -r '.extra.metadata.impact')
            message=$(echo "$f" | jq -r '.extra.message')
            # If you want to include all CWEs:
            cwe_list=$(echo "$f" | jq -r '.extra.metadata.cwe | join(",")')
            # Append rule ID + CWEs as "Finding" in CSV
            finding="$rule_id [$cwe_list]"
            add_finding "$finding" "$severity" "Semgrep" "$message"
        done
    fi
}


#jq -r '.results[] | [.extra.metadata.cwe[], .extra.metadata.impact, "Semgrep", .extra.message] | @csv'


run_nuclei() {
    if [[ "$ENABLE_NUCLEI" != "true" ]]; then return; fi
    echo -e "[+] Running \033[31;47;1mNuclei (advanced templates)\033[0m..."
    echo "[*]saving output into: $NUCLEI_OUT"
    $NUCLEI_CMD  -u $TARGET_URL -s critical,high,medium -json-export "$NUCLEI_OUT"

    if [[ -f "$NUCLEI_OUT" ]]; then
        # Iterate directly in jq and output CSV-safe lines
        jq -r '.[] | [
            .info.name,
            .info.severity,
            "Nuclei",
            .info.description
        ] | @csv' "$NUCLEI_OUT" 2>/dev/null >> "$OUTPUT_CSV"
    fi
}




###############################################################
#  SNYK (Advanced Dependency Scanning)
###############################################################
run_snyk() {
    if [[ "$ENABLE_SNYK" != "true" ]]; then return; fi
    echo -e "[+] Running \033[31;47;1mSnyk (advanced dependency scanning)\033[0m..."

    if [[ -n "$SNYK_TOKEN" ]]; then
        export SNYK_TOKEN="$SNYK_TOKEN"
    fi

    (
        cd "$SOURCE_CODE_PATH" || exit
        $SNYK_CMD test --all-projects --json > "$SNYK_OUT" 2>/dev/null
    )

    if [[ -f "$SNYK_OUT" ]]; then
        jq -c '.vulnerabilities[]' "$SNYK_OUT" | while read -r f; do
            title=$(echo "$f" | jq -r '.title')
            severity=$(echo "$f" | jq -r '.severity')
            desc=$(echo "$f" | jq -r '.description')
            add_finding "$title" "$severity" "Snyk" "$desc"
        done
    fi
}


###############################################################
#  NIKTO (Aggressive DAST Scan)
###############################################################
run_nikto() {
    if [[ "$ENABLE_NIKTO" != "true" ]]; then return; fi
    echo -e "[+] Running \033[31;47;1mNikto (aggressive mode)\033[0m..."
    echo "[*]saving output into: $NIKTO_OUT"
    $NIKTO_CMD \
        -h "$TARGET_URL" \
        -Cgidirs all \
        -ask no \
        -nointeractive -o "$NIKTO_OUT" -Format json 2>/dev/null
    
    if [[ -f "$NIKTO_OUT" ]]; then
        jq -c '.vulnerabilities[]' "$NIKTO_OUT" 2>/dev/null | while read -r f; do
            msg=$(echo "$f" | jq -r '.msg')
            severity="Not Defined"
            add_finding "Nikto Vulnerability finiding" "$severity" "Nikto" "$msg"
        done
        tmpfile="${NIKTO_OUT}.tmp"
        jq -c '.vulnerabilities[]' "$NIKTO_OUT" > "$tmpfile" 2>/dev/null
        mv "$tmpfile" "$NIKTO_OUT"
    fi
    
}



###############################################################
#  GITLEAKS (Secret Detection)
###############################################################
run_gitleaks() {
if [[ "$ENABLE_GITLEAKS" == "true" ]]; then
    echo -e "[+] Running \033[31;47;1mGitleaks\033[0m....."
    $GITLEAKS_CMD detect \
        --source "$SOURCE_CODE_PATH" \
        --report-format json \
        --report-path "${RESULTS_DIR}/gitleaks.json" \
        --no-banner \
        --redact=false \
        --verbose
fi
}

###############################################################
#  NMAP (Advanced NSE + Vulnerability Scripts)
###############################################################
run_nmap() {
    if [[ "$ENABLE_NMAP" != "true" ]]; then return; fi

    echo -e "[+] Running \033[31;47;1mNmap advanced scan\033[0m....."
    TARGET_HOST=$(echo "$TARGET_URL" | sed 's|http[s]\?://||' | cut -d/ -f1)

    $NMAP_CMD \
        -sV \
        --script vuln,default,http-vuln*,http-security-headers \
        -T4 \
        -oX "$NMAP_OUT" \
        "$TARGET_HOST" > /dev/null 2>&1

    if [[ -f "$NMAP_OUT" ]]; then
        grep -oP '(?<=<script id=").*?(?=")' "$NMAP_OUT" | while read -r script; do
            add_finding "$script" "info" "Nmap" "See Nmap XML for details"
        done
    fi
}



###############################################################
#  RUN ALL SCANNERS
###############################################################
echo -e "\e[31m             [WARNING!!] - Use this script only with Target's Permission           \e[0m"
echo
echo -e "\e[32m                           Author:\e[0m  \033[31;47;1mAhmed Reda - AKA. Minyawy\033[0m          "
echo
echo -e "[+] Starting \e[33mSecurify\e[33m..."
echo -e "[+] Target URL: \e[33m$TARGET_URL\e[0m"
echo -e "[+] Source Code Path: \e[33m$SOURCE_CODE_PATH\e[0m"
echo

run_semgrep
run_snyk
run_nikto
run_nmap
run_gitleaks
run_nuclei


echo
echo -e "[+] \e[33mSecurify Completed!\e[0m"
echo -e "[+] Results saved to: \e[33m$OUTPUT_CSV\e[0m"
