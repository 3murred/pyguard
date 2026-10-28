"""Small example of safer patterns; still review the whole application."""
import json
import subprocess

def parse_user_data(raw: str):
    # Data-only parsing is safer than eval/pickle for untrusted content.
    return json.loads(raw)

def run_tool():
    # Pass arguments separately; shell parsing is not requested.
    return subprocess.run(["python", "--version"], check=True, capture_output=True, text=True)
