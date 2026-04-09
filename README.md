# AI-SOC-Triage-Assistant
The lab ingests raw alert data, normalizes event fields, applies rule-based severity scoring, maps suspicious behavior to MITRE ATT&amp;CK, and generates analyst-style incident summaries. MITRE ATT&amp;CK organizes adversary behavior into tactics and techniques, which makes it a useful framework for triage output and communication.

The recommended scope focuses on suspicious PowerShell activity, brute-force login behavior, and unusual process execution paths. PowerShell abuse maps well to ATT&CK technique T1059.001, while brute-force activity maps to T1110, making them strong starter detections for this project.

## Skills and Relevancy

This project demonstrates practical skills in Python scripting, alert triage, structured detection logic, ATT&CK mapping, analyst-style documentation, and AI-assisted summarization. Guidance on AI-era SOC workflows consistently emphasizes automation, contextual triage, and analyst oversight, which makes this project a credible portfolio item for cybersecurity roles.

## Tools Required

Use the following free tools:

- Python 3.x
- VS Code
- Git
- GitHub
- pandas
- Ollama
