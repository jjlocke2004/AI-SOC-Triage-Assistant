import pandas as pd
from pathlib import Path

RAW_FILE = Path("data/raw_alerts/sample_alerts.csv")
OUT_FILE = Path("data/processed/normalized_alerts.csv")

def normalize_alerts():
    df = pd.read_csv(RAW_FILE)

    df = df.fillna("unknown")
    for col in ["host","user","event_type","process_name","parent_process","command_line","status","raw_message"]:
        df[col] = df[col].astype(str).str.strip()
    
    df["process_name"] = df["process_name"].str.lower()
    df["parent_process"] = df["parent_process"].str.lower()
    df["event_type"] = df["event_type"].str.lower()
    df["status"] = df["status"].str.lower()

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_FILE, index=False)
    return df

if __name__ == "__main__":
    normalize_alerts()