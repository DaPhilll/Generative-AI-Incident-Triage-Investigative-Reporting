"""
Pre-parsing step for the incident triage pipeline.
Strips a raw Wazuh alert down to the fields relevant for triage before
it reaches the model, to keep the prompt focused and reduce token usage.
"""
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
