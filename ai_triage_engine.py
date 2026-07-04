"""
Sends a cleaned log entry to the Gemini API and returns a structured
incident report. Requires GEMINI_API_KEY to be set in the environment.
"""
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
