# AI-Powered SOC Triage Assistant

This project is a simulation of a triage workflow of a lightweight Security Operations Center (SOC) created with Python and free local tooling. It consumes raw alert data, normalizes fields of events, uses rule-based severity scoring, maps suspicious activity to MITRE ATT&CK techniques, and produces analyst-friendly summaries to investigate. The idea was to integrate realistic cybersecurity processes with AI-like automation into a project that can be described and reproduced on a laptop and applied to the position of an entry-level SOC / Cybersecurity Analyst. 

---

## Objectives

- Parse and normalize raw security alerts to a standardized schema to be analyzed.
- Use weighted detection logic to detect suspicious behavior and provide severity.
- Map detections to MITRE ATT&CK techniques to characterize adversary behavior in common terms (e.g., T1059.001, T1110).
- Produce analyst-ready summaries that describe how, why and what to do next.
- Show how a local LLM (through Ollama) can support SOC triage without an analyst out of the loop.

---

## Architecture Overview

High-level data flow:

```text
Raw Alerts CSV
     ↓
Parser / Normalizer
     ↓
Detection & Severity Scoring
     ↓
MITRE ATT&CK Mapping
     ↓
AI / Template-Based Summary Generator
     ↓
CSV + Markdown Incident Report
```

Key components:

- **Parser (`src/parser.py`)**  
  Normalizes raw alert fields and outputs `data/processed/normalized_alerts.csv`.

- **Detection Engine (`src/detection_engine.py`)**  
  Applies rule-based heuristics and scoring, producing `data/processed/scored_alerts.csv`.

- **MITRE ATT&CK Mapping (`src/attack_mapping.py`)**  
  Maps detection categories to ATT&CK tactics/techniques (e.g., Execution / PowerShell, Brute Force).

- **Summarizer (`src/summarizer.py`)**  
  Generates an `analyst_summary` for each alert using:
  - A local LLM via Ollama for High/Critical alerts, and/or
  - Fast template-based summaries for lower severity alerts.

- **Report Generator (`src/report_generator.py`)**  
  Produces a Markdown report at `reports/incident_report.md` for human review.

- **Pipeline Orchestrator (`src/main.py`)**  
  Runs the full pipeline end to end.

---

## Tools & Technologies

- **Language:** Python 3
- **Libraries:** `pandas`, `requests`
- **AI Runtime:** [Ollama](https://ollama.com) running a local `llama3.2:1b` model
- **Detection Framework:** MITRE ATT&CK for tactic/technique mapping
- **Editor / Environment:** Visual Studio Code with a local virtual environment

---

## Dataset & Detection Logic

### Sample Alerts

The project uses a small synthetic dataset in `data/raw_alerts/sample_alerts.csv` containing a mix of:

- Suspicious PowerShell execution (including encoded commands).
- Repeated failed logon attempts from the same source IP (brute-force pattern).
- Executables running from `Temp` / `AppData`.
- PowerShell making outbound HTTP requests.
- Benign browser and PowerShell usage.

All IP addresses are synthetic (RFC1918 private or documentation ranges).

### Detection Rules

Alerts are scored based on weighted heuristics and then assigned a severity band:

| Rule                             | Score | Purpose                                             |
|----------------------------------|------:|-----------------------------------------------------|
| Encoded PowerShell               | 40    | Flag likely malicious PowerShell execution          |
| Office spawning PowerShell       | 35    | Catch suspicious parent-child behavior              |
| 5+ failed logons from one IP     | 45    | Detect brute-force login patterns                   |
| Temp/AppData execution           | 25    | Identify unusual executable locations               |
| PowerShell outbound connection   | 30    | Highlight script-based network activity             |

Severity bands:

- `0–19`  → Low  
- `20–39` → Medium  
- `40–69` → High  
- `70+`   → Critical  

---

## MITRE ATT&CK Mapping

Each detection category is mapped to a MITRE ATT&CK tactic and technique to standardize how alerts are described:

| Pattern                      | ATT&CK ID  | Technique                                        |
|-----------------------------|------------|--------------------------------------------------|
| Encoded PowerShell          | T1059.001  | Command and Scripting Interpreter: PowerShell    |
| Repeated failed logons      | T1110      | Brute Force                                      |
| Temp/AppData execution      | T1204      | User Execution                                   |
| PowerShell network activity | T1059.001  | Command and Scripting Interpreter: PowerShell    |
| Benign activity             | None       | None                                             |

These mappings are implemented in `src/attack_mapping.py` and attached to each alert by the detection engine.

---

## AI Summarization (Ollama)

The project optionally uses [Ollama](https://ollama.com) to run a local LLM (`llama3.2:1b`) for incident summarization:

- For each alert, the pipeline builds a structured prompt with:
  - Alert ID, timestamp, host, user, event type
  - Process / parent process / command line
  - Source/destination IPs
  - Score, severity, detection findings
  - MITRE ATT&CK mapping
- The prompt is sent to the local Ollama API (`http://localhost:11434/api/generate`).
- The model returns a short 3–4 sentence summary that explains:
  - What happened
  - Why it matters
  - 1–2 recommended next steps

On limited hardware or when Ollama is unavailable, the summarizer can fall back to fast, template-based summaries so the pipeline still completes. The intent is to **assist** the analyst, not replace them—summaries should be reviewed and validated before action.

---

## Outputs

Running the full pipeline produces:

- `data/processed/normalized_alerts.csv`  
  Cleaned version of the raw alerts.

- `data/processed/scored_alerts.csv`  
  Alerts with detection scores, severity, and ATT&CK mappings.

- `data/processed/final_triage.csv`  
  Fully enriched alerts including the `analyst_summary` column.

- `reports/incident_report.md`  
  Human-readable triage report with:
  - Executive summary (counts by severity)
  - Per-alert sections showing key fields, findings, score, ATT&CK mapping, and summary.

---

## How to Run the Project

1. **Clone the repository locally**

   ```bash
   git clone https://github.com/<your-username>/AI-SOC-Triage-Assistant.git
   cd AI-SOC-Triage-Assistant
   ```

2. **Create and activate a virtual environment**

   ```bash
   python -m venv .venv
   .venv\Scripts\activate   # Windows PowerShell / CMD
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **(Optional) Start Ollama and pull the model**

   Install Ollama for Windows and then:

   ```bash
   ollama pull llama3.2:1b
   ollama run llama3.2:1b   # keep this terminal open, or ensure ollama service is running
   ```

5. **Run the full triage pipeline**

   ```bash
   python src\main.py
   ```

6. **Review results**

   - `data/processed/final_triage.csv` – enriched alerts with summaries  
   - `reports/incident_report.md` – incident-style report

---

## Sample Findings

Examples of what the tool can surface:

- **Alert 1 – Critical PowerShell Execution**  
  Encoded PowerShell launched from `winword.exe` on `WIN10-01`, mapped to ATT&CK T1059.001 (PowerShell). The tool flags this as Critical due to encoded command use and the Office → PowerShell parent-child chain, recommending immediate host isolation and process lineage review.

- **Alerts 2–6 – High Brute Force Activity**  
  Multiple failed logons from the same external IP are grouped as High severity and mapped to T1110 (Brute Force). The tool suggests reviewing authentication logs, blocking the source, and checking for successful logons from the same IP.

- **Alert 7–8 – Medium Suspicious Execution / Network Activity**  
  Execution from `Temp\AppData` plus PowerShell making HTTP requests to an external address are tagged as Medium severity with recommendations to investigate the binary and check for related outbound connections.

---

## Screenshots

Screenshots (stored under `screenshots/`) illustrate the workflow:

- `01-project-structure.png` – VS Code workspace layout
- `02-raw-alerts.png` – Sample alerts dataset
- `03-normalized-alerts.png` – Normalized alerts output
- `04-detection-rules.png` – Detection engine code and scoring rules
- `05-terminal-run.png` – `python src/main.py` pipeline execution
- `06-final-triage-csv.png` – `final_triage.csv` with `analyst_summary`
- `07-incident-report-preview.png` – Markdown triage report
- `08-architecture-diagram.png` – Overall system diagram

---

## Skills Demonstrated

- Python scripting for security automation
- Log and alert parsing with `pandas`
- Rule-based detection engineering and severity scoring
- MITRE ATT&CK–aligned triage and documentation
- AI-assisted analysis using a local LLM (Ollama)
- Incident reporting and analyst-style communication
- Git / GitHub workflow and project documentation
