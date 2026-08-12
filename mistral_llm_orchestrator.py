import json
import datetime
import requests

INPUT_FILE = "IP_scan.json"
OUTPUT_FILE = "LLM_Final_Report.json"

MISTRAL_API_KEY = "GETsezHNPRSPKuxE0DWt0Rro8HMdgFjh"
MISTRAL_CHAT_URL = "https://api.mistral.ai/v1/chat/completions"

# Different models per task if you want
TASK_MODELS = {
    "security": "mistral-large-latest",
    "compliance": "mistral-large-latest",
    "risk": "mistral-large-latest"
}


with open(INPUT_FILE, "r") as f:
    scan_data = json.load(f)

def call_mistral(model, system_prompt, user_prompt):
    headers = {
        "Authorization": f"Bearer {MISTRAL_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
    }

    r = requests.post(MISTRAL_CHAT_URL, headers=headers, json=payload, timeout=120)
    r.raise_for_status()

    data = r.json()
    return data["choices"][0]["message"]["content"].strip()

# ----------------------------------------------------
# PROMPTS (DETAILED)
# ----------------------------------------------------
SECURITY_SYSTEM_PROMPT = """
You are a network security analyst.

You must analyze the given network device scan data and identify security issues using only the evidence in the scan.

Rules:
- Do not guess device type, OS, vendor, or software versions unless the scan clearly shows it.
- Do not invent vulnerabilities, CVEs, or exploit steps.
- If the scan data is incomplete, say so clearly.
- Use plain English.
- Use short sentences.
- Do not use hype or marketing tone.

Evidence rule:
For every claim, include one short evidence reference in brackets.
Example: [evidence: port 22 open, service ssh]
If no evidence exists, say "Not supported by scan evidence".

Output format:
1. Device Summary
2. Exposed Surface (ports and services)
3. Security Findings (each finding must cite evidence)
4. Likely Impact
5. Recommended Fixes (safe and realistic)
6. Notes and Limits
"""

SECURITY_USER_PROMPT = f"""
Analyze this scan JSON and produce a security posture summary.

You must:
- List open ports and detected services.
- Identify misconfigurations and weak exposure.
- Explain why each finding matters.
- Link each finding to scan evidence (port number, service name, banner, protocol).

Scan JSON:
{json.dumps(scan_data, indent=2)}
"""


RISK_SYSTEM_PROMPT = """
You are a cybersecurity risk analyst.

Your task is to assess risk for a scanned network device.

Rules:
- Base your assessment only on the scan evidence.
- Do not assume missing controls.
- Do not invent business context.
- Use a 3-level risk rating: Low, Medium, High.
- Explain the rating using scan facts.
- Do not mention CVSS unless scan data includes a known vulnerability reference.

Evidence rule:
For every claim, include one short evidence reference in brackets.
Example: [evidence: port 22 open, service ssh]
If no evidence exists, say "Not supported by scan evidence".

You must produce a risk result that a security manager can use.
Use plain English and short sentences.

Output format:
1. Risk Rating (Low/Medium/High)
2. Key Risk Drivers (3 to 6 bullet points)
3. Most Likely Attack Paths (2 to 4)
4. Business Impact (generic but realistic)
5. Risk Reduction Plan (ordered steps)
6. Notes and Limits
"""

RISK_USER_PROMPT = f"""
Assess risk for this device using scan evidence only.

You must:
- Decide Low, Medium, or High risk.
- Give a short justification.
- Identify likely attacker actions based on open services.
- Provide an ordered plan to reduce risk.

Scan JSON:
{json.dumps(scan_data, indent=2)}
"""


COMPLIANCE_SYSTEM_PROMPT = """
You are a compliance analyst for cybersecurity controls.

Your task is to map scan evidence from a network device to compliance control requirements.

The goal is not to certify compliance.
The goal is to estimate readiness and gaps based on technical evidence.

Rules:
- Use only scan evidence.
- Do not claim compliance for controls that need policy or documentation proof.
- If a control cannot be validated from scan data, mark it as "Not Verifiable".
- Do not invent audit evidence.
- Do not reference laws unless asked.
- Use plain English.

Evidence rule:
For every claim, include one short evidence reference in brackets.
Example: [evidence: port 443 open, service https]
If no evidence exists, say "Not supported by scan evidence".

Frameworks to use:
- ISO/IEC 27001 (Annex A high-level controls)
- NIST Cybersecurity Framework (Identify, Protect, Detect, Respond, Recover)

Output format:
1. Compliance Scope Assumption
2. ISO 27001 Mapping Table
3. NIST CSF Mapping Table
4. Gaps That Are Visible From Scan Evidence
5. Gaps That Need Manual Evidence (Not Verifiable)
6. Priority Fix Plan (ordered steps)
7. Notes and Limits
"""

COMPLIANCE_USER_PROMPT = f"""
Map this device scan evidence to ISO 27001 and NIST CSF.

You must:
- Only use evidence from the scan.
- Identify which controls appear supported by technical posture.
- Identify which controls appear missing.
- Mark controls as "Not Verifiable" if scan data cannot prove them.

You must include:
- A small ISO mapping table with 8 to 12 controls.
- A small NIST CSF mapping table with 8 to 12 functions/subcategories.

Scan JSON:
{json.dumps(scan_data, indent=2)}
"""

# ----------------------------------------------------
# ORCHESTRATOR
# ----------------------------------------------------
def run_task(task_name, system_prompt, user_prompt):
    model = TASK_MODELS[task_name]
    print(f"[*] Running {task_name.upper()} with Mistral model: {model}")
    return call_mistral(model, system_prompt, user_prompt)

# Run tasks
security_result = run_task("security", SECURITY_SYSTEM_PROMPT, SECURITY_USER_PROMPT)
compliance_result = run_task("compliance", COMPLIANCE_SYSTEM_PROMPT, COMPLIANCE_USER_PROMPT)
risk_result = run_task("risk", RISK_SYSTEM_PROMPT, RISK_USER_PROMPT)

# ----------------------------------------------------
# SAVE FINAL JSON
# ----------------------------------------------------
final_output = {
    "target_ip": scan_data.get("target_ip", "Unknown"),
    "generated_at": datetime.datetime.utcnow().isoformat(),
    "provider": "mistral",
    "models_used": TASK_MODELS,
    "results": {
        "security_analysis": security_result,
        "compliance_analysis": compliance_result,
        "risk_assessment": risk_result
    }
}

with open(OUTPUT_FILE, "w") as f:
    json.dump(final_output, f, indent=4)

print(f"[+] Done. Saved report as: {OUTPUT_FILE}")
