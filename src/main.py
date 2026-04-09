from parser import normalize_alerts
from detection_engine import run_detection
from summarizer import add_summaries
from report_generator import generate_report

def main():
    normalize_alerts()
    run_detection()
    add_summaries()
    generate_report()
    print("Pipeline complete. Outputs saved in data/processed/ and reports/")

if __name__ == "__main__":
    main()