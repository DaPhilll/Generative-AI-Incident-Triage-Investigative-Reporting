"""
CLI entry point for the incident triage pipeline.

Usage:
    python main_triage.py --log ./sample_alerts/example_alert.json --output ./reports/
"""
import argparse
import os

from log_parser import load_and_clean_log
from ai_triage_engine import generate_incident_report


def main():
    parser = argparse.ArgumentParser(description="Generate an incident triage report from a security log.")
    parser.add_argument("--log", required=True, help="Path to the raw log JSON file.")
    parser.add_argument("--output", required=True, help="Directory to write the generated report to.")
    args = parser.parse_args()

    if not os.getenv("GEMINI_API_KEY"):
        raise SystemExit("GEMINI_API_KEY is not set in the environment.")

    os.makedirs(args.output, exist_ok=True)

    cleaned_log = load_and_clean_log(args.log)
    report_text = generate_incident_report(cleaned_log)

    log_basename = os.path.splitext(os.path.basename(args.log))[0]
    output_path = os.path.join(args.output, f"Incident_Report_{log_basename}.md")

    with open(output_path, "w") as f:
        f.write(report_text)

    print(f"Report written to {output_path}")


if __name__ == "__main__":
    main()
