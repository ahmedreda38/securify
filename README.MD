
# **Securify – Unified SAST/DAST Automation Engine**

**Author:** Ahmed Reda (aka Minyawy)
**Project Type:** Security Automation & Vulnerability Scanning Framework
**Written In:** Bash
**Target Audience:** Security engineers, DevOps teams, penetration testers

---

## **Overview**

**Securify** is a professional, modular, and unified automation framework for **Static Application Security Testing (SAST)**, **Dynamic Application Security Testing (DAST)**, **dependency analysis**, and **secret detection**. The tool integrates industry-standard scanners and unifies their outputs into a single CSV report, making vulnerability assessment and auditing streamlined for developers and security engineers.

**Key Features:**

* Config-driven and CLI-based execution
* Advanced **SAST scanning** with Semgrep
* Comprehensive **dependency scanning** using Snyk
* Aggressive **DAST scans** via Nikto and Nuclei
* Secret detection using **Gitleaks**
* Network vulnerability scanning using **Nmap with NSE scripts**
* Unified, easy-to-read **CSV reporting**
* JSON outputs retained for detailed review
* Modular execution: enable/disable individual scanners

---

## **Directory Structure**

```
securify/
├── securify.sh               # Main automation script
├── securify.conf             # Configuration file
├── securify_results/         # Output directory
│   ├── findings.csv          # Unified CSV report
│   ├── semgrep.json          # Semgrep JSON output
│   ├── snyk.json             # Snyk JSON output
│   ├── nikto.json            # Nikto JSON output
│   ├── nmap.xml              # Nmap XML report
│   ├── nuclei.json           # Nuclei JSON output
│   └── gitleaks.json         # Gitleaks JSON output
```

---

## **Configuration (`securify.conf`)**

The configuration file allows **full customization of target, tools, outputs, and API keys**. Example:

```bash
# Target Configuration
TARGET_URL="http://127.0.0.1:4280"
SOURCE_CODE_PATH="/var/www/html/DVWA"
RESULTS_DIR="securify_results"

# Output Paths
OUTPUT_CSV="${RESULTS_DIR}/findings.csv"
SEMGRP_OUT="${RESULTS_DIR}/semgrep.json"
SNYK_OUT="${RESULTS_DIR}/snyk.json"
NIKTO_OUT="${RESULTS_DIR}/nikto.json"
NMAP_OUT="${RESULTS_DIR}/nmap.xml"
NUCLEI_OUT="${RESULTS_DIR}/nuclei.json"

# Tool Activation Flags
ENABLE_SEMGREP="false"
ENABLE_SNYK="false"
ENABLE_NIKTO="false"
ENABLE_NMAP="false"
ENABLE_GITLEAKS="false"
ENABLE_NUCLEI="true"

# Optional API Keys
SNYK_TOKEN=""

# Custom Tool Paths
SEMGREP_CMD="$(which semgrep)"
SNYK_CMD="$(which snyk)"
NIKTO_CMD="$(which nikto)"
NMAP_CMD="$(which nmap)"
JQ_CMD="$(which jq)"
GITLEAKS_CMD="$(which gitleaks)"
NUCLEI_CMD="$(which nuclei)"
```

**Pro Tips for Config Setup:**

* Always verify the path to each scanning tool using `which <tool>` to avoid execution errors.
* Enable only the tools relevant to the assessment to save runtime.
* Use **API keys** (like Snyk) to scan private repositories or exceed free limits.
* Separate output directories per engagement to avoid overwriting past results.

---

## **Command Line Usage**

```bash
./securify.sh --config-file securify.conf --repo-path ./myapp
```

**CLI Options:**

| Option        | Shortcut | Description                    |
| ------------- | -------- | ------------------------------ |
| --config-file | -c       | Path to configuration file     |
| --repo-path   | -r       | Path to source code repository |

---

## **Tool Integration Details**

### **1. Semgrep (Advanced SAST)**

* Scans source code for security issues, anti-patterns, and CWEs.
* **JSON output:** `$SEMGRP_OUT`
* **CSV output:** `Finding` = `<rule_id>[CWE]`, `Severity`, `Tool`, `Details`
* Advanced metadata parsing using `jq` to extract **impact, CWE, and message**.

**Advanced Options:**

* Can integrate custom rulesets: `semgrep --config /path/to/rules`
* Supports multiple languages: Python, PHP, JavaScript, Go, Java, etc.

---

### **2. Nuclei (Vulnerability Scanning via Templates)**

* Target: URL-based scanning
* Severity filter: critical, high, medium (`-s critical,high,medium`)
* JSON output: `$NUCLEI_OUT`
* CSV integration: includes `name`, `severity`, `tool`, `description`

**Advanced Options:**

* Supports custom templates: `-t /path/to/templates`
* Supports dynamic HTTP headers, authentication tokens

---

### **3. Snyk (Dependency Scanning)**

* Detects vulnerabilities in project dependencies
* Scans all projects: `--all-projects`
* Requires optional `SNYK_TOKEN` for private repos
* JSON output: `$SNYK_OUT`, parsed into CSV

**Advanced Options:**

* Language-specific scanning (npm, pip, Maven, Gradle, etc.)
* Integration with CI/CD pipelines for automated scanning

---

### **4. Nikto (Aggressive Web Vulnerability Scanner)**

* Detects outdated software, misconfigurations, and known vulnerabilities
* Aggressive options: `-Cgidirs all -ask no -nointeractive -Format json`
* JSON output: `$NIKTO_OUT`, CSV captures messages as `Details`

---

### **5. Gitleaks (Secret Detection)**

* Detects hard-coded secrets in source code
* JSON output: `$RESULTS_DIR/gitleaks.json`
* Options:

  * `--no-banner` → suppress startup banner
  * `--redact=false` → keep full secret values (use in safe environments)
  * `--verbose` → detailed output for troubleshooting

---

### **6. Nmap (Advanced NSE + Vulnerability Scripts)**

* Uses NSE scripts for default, HTTP-specific, and vulnerability checks
* Output: XML `$NMAP_OUT` + CSV summary of detected scripts
* Advanced options:

  * `-sV` → service version detection
  * `--script vuln,default,http-vuln*,http-security-headers`
  * `-T4` → faster scan timing template

---

## **CSV Output Structure**

Unified CSV reporting ensures all tool results are in a single place:

| Column   | Description                                                   |
| -------- | ------------------------------------------------------------- |
| Finding  | Vulnerability name, rule ID, or template                      |
| Severity | Criticality (critical, high, medium, info, Not Defined)       |
| Tool     | Source scanner (Semgrep, Nuclei, Snyk, Nikto, Nmap, Gitleaks) |
| Details  | Description, message, or evidence from scan                   |

**Example Row:**

```
"nuclei/cve-2025-1234.yaml","critical","Nuclei","SQL Injection vulnerability in login endpoint"
```

---

## **Execution Flow**

1. Parse CLI arguments and load configuration.
2. Validate `SOURCE_CODE_PATH` and tool paths.
3. Create results directory and initialize CSV.
4. Sequentially run each enabled tool:

   * Semgrep → Snyk → Nikto → Nmap → Gitleaks → Nuclei
5. Collect findings into `findings.csv` and JSON files.
6. Completion message with results location.

---

## **Professional Recommendations**

* **Run with proper permissions only:** Never run against unauthorized targets.
* **Environment setup:** Use Python virtualenv or Docker for isolated tool dependencies.
* **CI/CD Integration:** Hook `securify.sh` into Jenkins, GitHub Actions, or GitLab CI for automated scanning.
* **Custom Templates:** Extend Nuclei, Semgrep, and Gitleaks templates for organization-specific rules.
* **Reporting:** Use `findings.csv` as input to dashboards or vulnerability management systems.

---

## **Example Execution**

```bash
./securify.sh -c securify.conf -r /var/www/html/DVWA
```

Output:

```
[+] Starting Securify...
[+] Target URL: http://127.0.0.1:4280
[+] Source Code Path: /var/www/html/DVWA
[+] Running Nuclei (advanced templates)...
[+] Securify Completed!
[+] Results saved to: securify_results/findings.csv
```

---

## **Conclusion**

Securify is a **professional-grade, modular, and extensible scanning automation engine**. It consolidates multiple security tools, producing unified outputs in CSV and JSON. Its modular design allows it to be **used in penetration tests, CI/CD pipelines, and security audits**, demonstrating advanced expertise in automation, Bash scripting, and security tooling.

---

