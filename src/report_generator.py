import pandas as pd
from pathlib import Path

IN_FILE = Path("data/processed/final_triage.csv")
OUT_FILE = Path("reports/incident_report.md")

def generate_report():
    df = pd.read_csv(IN_FILE)

    lines = []
    lines.append("# AI-Powered SOC Triage Report\n")
    lines.append("## Executive Summary\n")
    lines.append(f"- Total alerts analyzed: {len(df)}\n")
    lines.append(f"- High/Critical alerts: {len(df[df['severity'].isin(['High', 'Critical'])])}\n")
    lines.append(f"- Medium alerts: {len(df[df['severity'] == 'Medium'])}\n")
    lines.append(f"- Low alerts: {len(df[df['severity'] == 'Low'])}\n\n")

    lines.append("## Alert Findings\n")
    for _, row in df.iterrows():
        lines.append(f"### Alert {row['alert_id']} - {row['severity']}\n")
        lines.append(f"- **Timestamp:** {row['timestamp']}\n")
        lines.append(f"- **Host:** {row['host']}\n")
        lines.append(f"- **User:** {row['user']}\n")
        lines.append(f"- **Event Type:** {row['event_type']}\n")
        lines.append(f"- **Findings:** {row['findings']}\n")
        lines.append(f"- **Score:** {row['score']}\n")
        lines.append(f"- **MITRE ATT&CK:** {row['attack_id']} - {row['technique']}\n")
        lines.append(f"- **Summary:** {row['analyst_summary']}\n")
        lines.append("")

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text("\n".join(lines), encoding="utf-8")

if __name__ == "__main__":
    generate_report()