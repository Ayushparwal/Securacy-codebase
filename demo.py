"""
Business Logic Threat Analyzer — simple Groq-powered demo
---------------------------------------------------------
Run:
  pip install groq streamlit
  # Windows PowerShell:
  $env:GROQ_API_KEY="your_groq_api_key"
  streamlit run threat_analyzer_demo.py

The app sends the system description to Groq and asks for the assignment's
three-stage analysis and JSON output. Treat results as hypotheses, not a
substitute for a security review.
"""
import json
import os
import re
import streamlit as st
from groq import Groq

st.set_page_config(page_title="Business Logic Threat Analyzer", page_icon="🛡️", layout="wide")

SYSTEM_PROMPT = r"""
You are a Principal Application Security Engineer specializing in business
logic threat modeling. Analyze the supplied software description rigorously,
ground findings in the description, and distinguish facts from assumptions.
Never claim an unspecified control is definitely absent. Do not invent endpoints,
roles, technologies, or workflows as established facts.

Perform these stages in order:
1. EXTRACT: external entities; features and workflow steps; business rules;
   sensitive data; stated controls; missing or unclear controls.
2. MAP WORKFLOWS TO RISKS: identify limits, approvals, permissions, required
   ordering, one-time-use rules, state transitions, and transaction invariants.
   Consider relevant bypasses, unauthorized actions, replay, concurrency,
   invalid values, partial updates, transaction integrity, and data exposure.
3. GENERATE THREATS: exactly 10 distinct, scenario-specific potential business
   logic threats, covering at least 6 of the 12 categories below.

Permitted categories (use exact names):
1. Out-of-order or skipped steps
2. Race conditions
3. API misconfiguration and enforcement gaps
4. Invalid or negative values
5. Input validation
6. Permission and authorisation failures
7. Idempotency and replay
8. Resource exhaustion and quota abuse
9. Concurrency
10. Database atomicity
11. Critical transaction integrity
12. Sensitive data confidentiality

Every threat must name an affected feature and a specific workflow step, explain
the violated business rule, give a plausible step-by-step hypothetical attack,
describe business impact, state assumptions/unknowns, assign severity
(Critical, High, Medium, or Low), and provide a concrete mitigation.

Do not confuse a missing detail with a confirmed vulnerability. Avoid generic
findings and duplicates. Distinct threats should have materially different root
causes, attack paths, or consequences. If details are missing, label the threat
as conditional and explain what needs verification.

Before answering, silently check: exactly 10 threats; IDs BL01 through BL10;
at least 6 distinct permitted categories; all required fields; no duplicates;
valid JSON; and no unsupported claims.

Return JSON only, with this exact top-level structure and no extra keys:
{
  "extraction": {
    "external_entities": ["..."],
    "features": [{"name": "...", "steps": ["..."], "business_rules": ["..."]}],
    "sensitive_data": ["..."],
    "stated_controls": ["..."],
    "missing_or_unclear_controls": ["..."]
  },
  "business_logic_threats": [
    {
      "id": "BL01",
      "category": "one of the 12 permitted categories",
      "title": "...",
      "affected_feature": "...",
      "workflow_step": "...",
      "business_rule_violated": "...",
      "attack_scenario": "...",
      "business_impact": "...",
      "assumption": "...",
      "severity": "Critical | High | Medium | Low",
      "mitigation": "..."
    }
  ]
}
"""

QUICKCART_EXAMPLE = """QuickCart is an online shopping application. Customers create accounts using
email and passwords. They can add products to their cart, apply discount coupons,
pay through an external payment gateway, and request refunds within seven days
of delivery. Each coupon can be used once per customer. Orders above ₹5,000
require additional payment verification. Sellers receive payouts every week
after refunds are deducted. Customer support agents can approve refunds up to
₹2,000; larger refunds require a manager's approval. The application uses a
REST API, JWT authentication, and a PostgreSQL database. Payment confirmations
arrive through webhooks. The description does not specify webhook verification,
coupon enforcement implementation, or database transaction handling."""

REQUIRED_CATEGORIES = {
    "Out-of-order or skipped steps",
    "Race conditions",
    "API misconfiguration and enforcement gaps",
    "Invalid or negative values",
    "Input validation",
    "Permission and authorisation failures",
    "Idempotency and replay",
    "Resource exhaustion and quota abuse",
    "Concurrency",
    "Database atomicity",
    "Critical transaction integrity",
    "Sensitive data confidentiality",
}
REQUIRED_THREAT_FIELDS = {
    "id", "category", "title", "affected_feature", "workflow_step",
    "business_rule_violated", "attack_scenario", "business_impact",
    "assumption", "severity", "mitigation",
}
REQUIRED_EXTRACTION_FIELDS = {
    "external_entities", "features", "sensitive_data", "stated_controls",
    "missing_or_unclear_controls",
}

def extract_json(text: str):
    """Parse JSON directly, with a fallback for accidental Markdown fences."""
    candidate = text.strip()
    candidate = re.sub(r"^```(?:json)?\s*", "", candidate, flags=re.IGNORECASE)
    candidate = re.sub(r"\s*```$", "", candidate)
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start >= 0 and end > start:
            return json.loads(candidate[start:end + 1])
        raise

def validate_result(data):
    errors = []
    if not isinstance(data, dict):
        return ["Top-level JSON value must be an object."]
    if set(data.keys()) != {"extraction", "business_logic_threats"}:
        errors.append("Top-level keys must be exactly 'extraction' and 'business_logic_threats'.")
    extraction = data.get("extraction")
    threats = data.get("business_logic_threats")
    if not isinstance(extraction, dict):
        errors.append("'extraction' must be an object.")
    else:
        missing = REQUIRED_EXTRACTION_FIELDS - set(extraction.keys())
        if missing:
            errors.append("Missing extraction fields: " + ", ".join(sorted(missing)))
        if not isinstance(extraction.get("features", []), list):
            errors.append("'features' must be a list.")
        else:
            for i, feature in enumerate(extraction["features"]):
                if not isinstance(feature, dict) or not {"name", "steps", "business_rules"}.issubset(feature):
                    errors.append(f"Feature at index {i} must include name, steps, business_rules.")
    if not isinstance(threats, list):
        errors.append("'business_logic_threats' must be a list.")
        return errors
    if len(threats) != 10:
        errors.append(f"Expected exactly 10 threats; received {len(threats)}.")
    categories = set()
    ids = []
    titles = []
    for i, threat in enumerate(threats):
        if not isinstance(threat, dict):
            errors.append(f"Threat at index {i} must be an object.")
            continue
        missing = REQUIRED_THREAT_FIELDS - set(threat.keys())
        if missing:
            errors.append(f"Threat at index {i} missing fields: {', '.join(sorted(missing))}.")
        if threat.get("category") not in REQUIRED_CATEGORIES:
            errors.append(f"Threat at index {i} has an invalid category.")
        else:
            categories.add(threat["category"])
        ids.append(threat.get("id"))
        titles.append(str(threat.get("title", "")).strip().lower())
        if threat.get("severity") not in {"Critical", "High", "Medium", "Low"}:
            errors.append(f"Threat at index {i} has an invalid severity.")
    if len(set(ids)) != len(ids) or set(ids) != {f"BL{i:02d}" for i in range(1, 11)}:
        errors.append("Threat IDs must be unique and run from BL01 through BL10.")
    if len(categories) < 6:
        errors.append(f"Only {len(categories)} distinct categories found; at least 6 are required.")
    nonempty_titles = [t for t in titles if t]
    if len(set(nonempty_titles)) != len(nonempty_titles):
        errors.append("Duplicate threat titles detected; manually check for duplicate underlying weaknesses.")
    return errors

st.title("🛡️ Business Logic Threat Analyzer")
st.caption("Groq-powered demo • Extract → Map workflow risks → Generate and validate JSON")
st.info("Treat generated findings as hypotheses for review, not proof that a vulnerability exists.")

with st.sidebar:
    st.header("Settings")
    model = st.text_input("Groq model", value="qwen/qwen3.8-27b",
                          help="Choose a model available to your Groq account.")
    api_key = st.text_input(
        "Groq API key",
        value=os.getenv("GROQ_API_KEY", ""),
        type="password",
        help="Prefer setting GROQ_API_KEY as an environment variable."
    )
    st.caption("Your API key is used by this local app to call Groq. Do not commit it to GitHub.")

col1, col2 = st.columns([3, 1])
with col1:
    system_description = st.text_area(
        "Software system description",
        height=320,
        placeholder="Paste the complete software system description here..."
    )
with col2:
    st.subheader("Quick start")
    if st.button("Load QuickCart demo", use_container_width=True):
        st.session_state["description"] = QUICKCART_EXAMPLE
        st.rerun()
    st.markdown("**Expected output**")
    st.markdown("- System extraction")
    st.markdown("- Exactly 10 threat hypotheses")
    st.markdown("- JSON validation report")
    st.markdown("- Downloadable JSON")

if "description" in st.session_state and not system_description:
    system_description = st.session_state["description"]

run = st.button("Analyze system", type="primary", use_container_width=True)

if run:
    if not api_key.strip():
        st.error("Add your Groq API key in the sidebar or set the GROQ_API_KEY environment variable.")
        st.stop()
    if len(system_description.strip()) < 40:
        st.error("Paste a meaningful system description first.")
        st.stop()

    client = Groq(api_key=api_key.strip())
    with st.spinner("Analyzing workflows and generating threat model..."):
        try:
            response = client.chat.completions.create(
                model=model.strip(),
                temperature=0.1,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": (
                        "Analyze the system description below using all three stages. "
                        "Return only the required JSON object.\n\n"
                        "SYSTEM DESCRIPTION:\n" + system_description.strip()
                    )},
                ],
            )
            raw_output = response.choices[0].message.content or ""
            result = extract_json(raw_output)
            errors = validate_result(result)
            st.session_state["last_raw"] = raw_output
            st.session_state["last_result"] = result
            st.session_state["last_errors"] = errors
        except Exception as exc:
            st.error(f"Analysis failed: {exc}")
            st.stop()

if "last_result" in st.session_state:
    result = st.session_state["last_result"]
    errors = st.session_state["last_errors"]

    st.divider()
    st.subheader("Validation")
    if errors:
        st.warning("The output needs review. Structural checks found:")
        for error in errors:
            st.write(f"- {error}")
    else:
        st.success("JSON structure and basic assignment checks passed. This does not prove threat accuracy or completeness.")

    extraction = result.get("extraction", {})
    t1, t2, t3 = st.tabs(["Extraction", "Threats", "Raw JSON"])

    with t1:
        for key, label in [
            ("external_entities", "External entities"),
            ("sensitive_data", "Sensitive data"),
            ("stated_controls", "Stated controls"),
            ("missing_or_unclear_controls", "Missing or unclear controls"),
        ]:
            st.markdown(f"**{label}**")
            st.write(extraction.get(key, []))
        st.markdown("**Features and workflows**")
        st.json(extraction.get("features", []))

    with t2:
        threats = result.get("business_logic_threats", [])
        for threat in threats:
            with st.expander(
                f"{threat.get('id', '??')} — {threat.get('title', 'Untitled')} "
                f"({threat.get('severity', 'Unknown')})"
            ):
                st.markdown(f"**Category:** {threat.get('category', '')}")
                st.markdown(f"**Affected feature:** {threat.get('affected_feature', '')}")
                st.markdown(f"**Workflow step:** {threat.get('workflow_step', '')}")
                st.markdown(f"**Business rule violated:** {threat.get('business_rule_violated', '')}")
                st.markdown(f"**Attack scenario:** {threat.get('attack_scenario', '')}")
                st.markdown(f"**Business impact:** {threat.get('business_impact', '')}")
                st.markdown(f"**Assumption:** {threat.get('assumption', '')}")
                st.markdown(f"**Mitigation:** {threat.get('mitigation', '')}")

    with t3:
        st.json(result)
        st.download_button(
            "Download JSON",
            data=json.dumps(result, indent=2, ensure_ascii=False),
            file_name="business_logic_threat_model.json",
            mime="application/json",
            use_container_width=True,
        )
        st.download_button(
            "Download raw model response",
            data=st.session_state["last_raw"],
            file_name="business_logic_threat_model_raw.txt",
            mime="text/plain",
            use_container_width=True,
        )

st.divider()
st.caption("Demo only: validation checks output shape and category coverage, not whether every finding is correct or exploitable.")
