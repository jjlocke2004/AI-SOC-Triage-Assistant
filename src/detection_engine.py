import pandas as pd
from pathlib import Path
from attack_mapping import ATTACK_MAP
 
IN_FILE = Path("data/processed/normalized_alerts.csv")
OUT_FILE = Path("data/processed/scored_alerts.csv")

def classify_alert(row, failed_login_counts):
    score = 0
    findings= []
    category = "benign"

    cmd = str(row["command_line"]).lower()
    process_name = str(row["process_name"]).lower()
    parent_process = str(row["parent_process"]).lower()
    event_type = str(row["event_type"]).lower()
    src_ip = str(row["src_ip"])

    if "powershell.exe" in process_name and "-enc" in cmd:
        score += 40
        findings.append("Encoded PowerShell command detected")
        category = "encoded_powershell"
    
    if parent_process in ["winword.exe","excel.exe"] and "powershell.exe" in process_name:
        score += 35
        findings.append("Suspicious Office-to-PowerShell execution")
        category = "encoded_powershell"

    if event_type == "logon_failed" and failed_login_counts.get(src_ip,0)>= 5:
        score += 45
        findings.append("Repeated failed logons from same source IP")
        category = "brute_force"
    
    if "temp" in cmd or "appdata" in cmd:
        score += 25
        findings.append("Executable launced from Temp/AppData path")
        category = "temp_execution"
    
    if event_type == "network_connection" and "powershell.exe" in process_name:
        score += 30
        findings.append("Powershell initiated outbound network connection")
        category = "poweshell_network"
    
    if score >= 70:
        severity = "Critical"
    elif score >= 40:
        severity = "High"
    elif score >= 20:
        severity = "Medium"
    else:
        severity = "Low"
    
    mapping = ATTACK_MAP.get(category, ATTACK_MAP ["benign"])

    return pd.Series({
        "score": score,
        "severity": severity,
        "findings": "; ".join(findings) if findings else
        "No major suspicious indicators",
        "tactic": mapping["tactic"],
        "technique": mapping["technique"],
        "attack_id": mapping["attack_id"],
          })

def run_detection():
    df = pd.read_csv(IN_FILE)

    failed_login_counts = (
        df[df["event_type"] == "logon_failed"]["src_ip"]
        .value_counts()
        .to_dict()
    )

    results = df.apply(lambda row: classify_alert (row,failed_login_counts), axis=1)
    final_df = pd.concat([df, results], axis=1)

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    final_df.to_csv(OUT_FILE, index=False)
    return final_df

if __name__ == "__main__":
    run_detection()

               