import pandas as pd
from pathlib import Path
import requests
import json

IN_FILE = Path("data/processed/scored_alerts.csv")
OUT_FILE = Path("data/processed/final_triage.csv")

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.2:1b" 

def call_ollama(prompt: str) -> str:
    """Call local Ollama model and return the full reponse as a string."""
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": True,
        "options": {
            "temperature": 0.2,
            "max_tokens": 220
        }
    }

    text_chunks = []

    with requests.post(OLLAMA_URL, json=payload, stream=True) as resp:
        resp.raise_for_status()
        for line in resp.iter_lines():
            if not line:
                continue
            obj = json.loads(line.decode("utf-8"))
            chunk = obj.get("response")
            if chunk:
                text_chunks.append(chunk)

    return "".join(text_chunks).strip()

def build_prompt(row) -> str:
    """Create a concise SOC-style prompt for the LLM."""
    return (
        "You are a SOC analyst. Write a concise 3-4 semtence incident summary for the following alert"
        "Explain what happened, why is matters, and 2 recommended next steps."
        "Use clear, professional language and do not invent extra data. /n/n"
        f"Alert ID: {row['alert_id']}\n"
        f"Timestamp: {row['timestamp']}\n"
        f"Host: {row['host']}\n"
        f"User: {row['user']}\n"
        f"Event Type: {row['event_type']}\n"
        f"Process: {row['process_name']}\n"
        f"Parent Process: {row['parent_process']}\n"
        f"Command Line: {row['command_line']}\n"
        f"Source IP: {row['src_ip']}\n"
        f"Destination IP: {row['dest_ip']}\n"
        f"Score: {row['score']}\n"
        f"Severity: {row['severity']}\n"
        f"Findings: {row['findings']}\n"
        f"MITRE ATT&CK: {row['attack_id']} - {row['technique']}\n"
    )

def generate_summary(row):
    prompt = build_prompt(row)
    print("Calling Ollama for alert", row["alert_id"])  # debug

    try:
        summary = call_ollama(prompt)
        print("Got response for alert", row["alert_id"])  # debug
        if not summary:
            raise ValueError("Empty response from model")
    except Exception as e:
        print("Error for alert", row["alert_id"], "->", e)  # debug
        summary = (
            f"LLM summary unavailable (error: {e}). "
            f"Manual summary: alert {row['alert_id']} on host {row['host']} "
            f"with severity {row['severity']} and findings: {row['findings']}."
        )
    return summary
    
def add_summaries():
    df = pd.read_csv(IN_FILE)
    df["analyst_summary"] = df.apply(generate_summary, axis=1)
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_FILE, index=False)
    print("Summaries added for", len(df), "alerts")
    return df
    
if __name__ == '__main__':
     add_summaries()