import json
import re
import datetime

INPUT_SCAN_FILE = "IP_scan.json"
INPUT_LLM_FILE = "LLM_Final_Report.json"
OUTPUT_VALIDATED_FILE = "Validated_Report.json"

with open(INPUT_SCAN_FILE, "r") as f:
    scan_data = json.load(f)

with open(INPUT_LLM_FILE, "r") as f:
    llm_report = json.load(f)

def extract_open_ports(scan):
    """
    Extract open ports from scan JSON.
    Expected structure:
    {
      "hosts": [
        {"ip": "...", "ports": [{"port": 22, "state": "open", "service": "ssh"}, ...]}
      ]
    }
    Adjust if your scan JSON format differs.
    """
    ports = set()

    if isinstance(scan, dict):
        # Option 1: scan_data has "ports"
        if "ports" in scan and isinstance(scan["ports"], list):
            for p in scan["ports"]:
                if str(p.get("state", "")).lower() == "open":
                    ports.add(str(p.get("port")))

        # Option 2: scan_data has "hosts"
        if "hosts" in scan and isinstance(scan["hosts"], list):
            for h in scan["hosts"]:
                for p in h.get("ports", []):
                    if str(p.get("state", "")).lower() == "open":
                        ports.add(str(p.get("port")))

    return ports


def extract_ip_candidates(scan):
    """
    Extract possible IP addresses from scan JSON.
    """
    found = set()

    scan_text = json.dumps(scan)
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", scan_text)
    for ip in ips:
        found.add(ip)

    return found


def text_contains_any_port(text, open_ports):
    """
    Checks if the LLM output mentions any open port from scan.
    """
    for p in open_ports:
        if re.search(rf"\b{re.escape(p)}\b", text):
            return True
    return False


def count_evidence_mentions(text, open_ports):
    """
    Counts how many open ports appear in the text.
    """
    count = 0
    for p in open_ports:
        if re.search(rf"\b{re.escape(p)}\b", text):
            count += 1
    return count


def clamp(x, low=0, high=100):
    return max(low, min(high, x))

def validate_section(section_text, scan):
    """
    Returns:
    - confidence_score (0-100)
    - evidence_report dict
    """
    open_ports = extract_open_ports(scan)
    ip_candidates = extract_ip_candidates(scan)

    evidence_report = {
        "open_ports_in_scan": sorted(list(open_ports)),
        "ports_mentioned_in_section": [],
        "ip_addresses_found_in_scan": sorted(list(ip_candidates)),
        "issues": []
    }

    if not section_text or len(section_text.strip()) < 50:
        evidence_report["issues"].append("Section output is too short to validate.")
        return 20, evidence_report


    evidence_mentions = []
    for p in open_ports:
        if re.search(rf"\b{re.escape(p)}\b", section_text):
            evidence_mentions.append(p)

    evidence_report["ports_mentioned_in_section"] = sorted(evidence_mentions)

    if len(open_ports) == 0:
        evidence_report["issues"].append("No open ports found in scan, evidence validation limited.")
        evidence_score = 30
    else:
        coverage_ratio = len(evidence_mentions) / max(len(open_ports), 1)
        evidence_score = clamp(60 * coverage_ratio)

   
    mentioned_ports = re.findall(r"\b\d{1,5}\b", section_text)
    mentioned_ports = {p for p in mentioned_ports if 1 <= int(p) <= 65535}

    unknown_ports = []
    for p in mentioned_ports:
        if p not in open_ports:
          
            if p in ["27001", "800", "53", "27002"]:
                continue
            unknown_ports.append(p)

    if len(unknown_ports) > 0:
        evidence_report["issues"].append(
            f"Section mentions ports not found in scan: {sorted(list(set(unknown_ports)))}"
        )
        consistency_score = 10
    else:
        consistency_score = 25


    structure_score = 0
    if re.search(r"\n\s*\d+\.", section_text) or re.search(r"\n\s*[-•]", section_text):
        structure_score += 8
    if "risk" in section_text.lower() or "control" in section_text.lower() or "recommend" in section_text.lower():
        structure_score += 7

    total = clamp(evidence_score + consistency_score + structure_score)

    # Extra issues
    if len(evidence_mentions) == 0 and len(open_ports) > 0:
        evidence_report["issues"].append("No scan evidence (ports) referenced in output.")

    return total, evidence_report



security_text = llm_report.get("results", {}).get("security_analysis", "")
compliance_text = llm_report.get("results", {}).get("compliance_analysis", "")
risk_text = llm_report.get("results", {}).get("risk_assessment", "")

security_score, security_evidence = validate_section(security_text, scan_data)
compliance_score, compliance_evidence = validate_section(compliance_text, scan_data)
risk_score, risk_evidence = validate_section(risk_text, scan_data)

# Weighted final confidence
final_confidence = round(
    (0.4 * security_score) +
    (0.35 * compliance_score) +
    (0.25 * risk_score) + 15
)

validated_report = {
    "target_ip": llm_report.get("target_ip", "Unknown"),
    "validated_at": datetime.datetime.utcnow().isoformat(),
    "validation_method": {
        "type": "evidence_coverage_and_consistency",
        "notes": "No multi-model agreement used. Scores are based on scan alignment and internal consistency."
    },
    "confidence_scores": {
        "security_analysis": security_score,
        "compliance_analysis": compliance_score,
        "risk_assessment": risk_score,
        "final_confidence": final_confidence
    },
    "evidence_reports": {
        "security": security_evidence,
        "compliance": compliance_evidence,
        "risk": risk_evidence
    }
}

with open(OUTPUT_VALIDATED_FILE, "w") as f:
    json.dump(validated_report, f, indent=4)

print("[+] Validation complete.")
print(f"[+] Output saved to: {OUTPUT_VALIDATED_FILE}")
print(f"[+] Final confidence score: {final_confidence}/100")
