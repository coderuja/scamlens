import re

import streamlit as st
from scamlens import analyze_message


SECTION_NAMES = [
    "RISK",
    "SCAM TYPE",
    "WARNING SIGNS",
    "WHAT THE SENDER WANTS",
    "RECOMMENDED ACTION",
    "CONFIDENCE",
]


def result_as_text(result) -> str:
    """Accept either backend text or the AgentResult used by some Strands versions."""
    if isinstance(result, str):
        return result

    message = getattr(result, "message", None)
    if isinstance(message, dict):
        content = message.get("content", [])
        if content:
            first_item = content[0]
            if isinstance(first_item, dict) and first_item.get("text"):
                return first_item["text"]
            if getattr(first_item, "text", None):
                return first_item.text

    return str(result)


def parse_analysis(result) -> dict:
    """Turn the backend's structured plain-text result into UI sections."""
    sections = {name: "" for name in SECTION_NAMES}
    headings = "|".join(re.escape(name) for name in SECTION_NAMES)
    parts = re.split(rf"(?im)^({headings})\s*:\s*", result_as_text(result).strip())

    for index in range(1, len(parts), 2):
        sections[parts[index].upper()] = parts[index + 1].strip()

    return sections


def show_warning_signs(warning_signs: str) -> None:
    """Display each warning sign as an easy-to-scan bullet."""
    signs = [line.strip("-• \t") for line in warning_signs.splitlines()]
    signs = [sign for sign in signs if sign]

    if signs:
        for sign in signs:
            st.markdown(f"🔴 {sign}")
    else:
        st.info("No warning signs were returned for this message.")
# ----------------------------------------
# Page configuration
# ----------------------------------------
st.set_page_config(
    page_title="ScamLens",
    page_icon="🛡️",
    layout="centered")
# ----------------------------------------
# Header
# ----------------------------------------
st.title("🛡️ ScamLens")
st.subheader("Think before you click.")
st.write(
    "Analyze a suspicious SMS, WhatsApp message, email, "
    "or payment request and understand the warning signs.")
# ----------------------------------------
# Message input
# ----------------------------------------
message = st.text_area(
    "Paste the suspicious message",
    height=220,
    placeholder=(
        "Example:\n""URGENT! Your bank account will be blocked today..."))
# ----------------------------------------
# Analyze button
# ----------------------------------------
if st.button("🔍 Analyze Message", use_container_width=True):
    if not message.strip():
        st.warning("Please paste a message first.")
    else:
        with st.spinner("ScamLens is analyzing the message..."):
            result = analyze_message(message)
        report = parse_analysis(result)
        risk = report["RISK"] or "UNCLEAR"
        risk_upper = risk.upper()

        if "HIGH" in risk_upper:
            icon, color = "⚠️", "#d83a3a"
        elif "MEDIUM" in risk_upper:
            icon, color = "⚠️", "#d9822b"
        else:
            icon, color = "✅", "#258344"

        st.divider()
        st.subheader("🔎 ScamLens Analysis")
        st.markdown(
            f"<div style='padding: 1rem; border: 2px solid {color}; "
            f"border-radius: 0.5rem; text-align: center;'>"
            f"<strong style='font-size: 1.5rem;'>{icon} {risk_upper} RISK</strong>"
            f"<br>{report['SCAM TYPE'] or 'Scam type unclear'}"
            f"</div>",
            unsafe_allow_html=True,
        )

        st.subheader("🔎 Why ScamLens flagged this")
        show_warning_signs(report["WARNING SIGNS"])

        sender_column, action_column = st.columns(2)
        with sender_column:
            st.subheader("🎯 What the sender wants")
            st.write(report["WHAT THE SENDER WANTS"] or "Not enough detail returned.")
        with action_column:
            st.subheader("🛡️ Recommended action")
            st.write(report["RECOMMENDED ACTION"] or "Verify independently before acting.")

        st.caption(f"Confidence: {report['CONFIDENCE'] or 'Not provided'}")

        # If the model changes its output format, the user can still read it.
        if not any(report.values()):
            st.info("The result was not in the usual format. Here is the full response:")
            st.code(result_as_text(result))
# ----------------------------------------
# Safety disclaimer
# ----------------------------------------
st.divider()
st.caption(
    "ScamLens provides an AI-based risk assessment. "
    "It is not a guaranteed determination of fraud."
)
