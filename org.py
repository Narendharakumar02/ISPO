import subprocess
import json

def run_network_scan():
    print("Running network scan...")
    subprocess.run(["python", "network_scanner.py"], check=True)

def run_llm_orchestrator():
    print("Running LLM orchestrator...")
    subprocess.run(["python", "mistral_llm_orchestrator.py"], check=True)

def run_validator():
    print("Running validator layer...")
    subprocess.run(["python", "validator_layer.py"], check=True)

def generate_pdf():
    print("Generating PDF...")
    subprocess.run(["python", "json_to_pdf_report.py"], check=True)

if __name__ == "__main__":
    run_network_scan()
    run_llm_orchestrator()
    run_validator()
    generate_pdf()
    print("Pipeline completed successfully!")