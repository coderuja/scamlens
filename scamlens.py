import os
import re

from strands import Agent
from signals import detect_signals


# --------------------------------------------------
# 1. Environment & Model Setup (Bedrock or Local Ollama)
# --------------------------------------------------
def _load_env():
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip("'\""))


_load_env()

bedrock_key = os.environ.get("BEDROCK_API_KEY")
bedrock_region = os.environ.get("AWS_DEFAULT_REGION", "eu-north-1")
bedrock_model_id = os.environ.get("BEDROCK_MODEL_ID", "amazon.nova-lite-v1:0")

if bedrock_key:
    from strands.models.bedrock import BedrockModel

    model = BedrockModel(
        model_id=bedrock_model_id,
        region_name=bedrock_region,
        api_key=bedrock_key,
    )
else:
    from strands.models.ollama import OllamaModel

    model = OllamaModel(
        host="http://localhost:11434",
        model_id="llama3.1",
    )

# --------------------------------------------------
# 2. ScamLens reasoning instructions
# --------------------------------------------------
SCAMLENS_PROMPT = """
You are ScamLens, a cybersecurity awareness and scam-detection assistant.
This is a DEFENSIVE CLASSIFICATION TASK.
The user provides a message they received. Your job is ONLY to
identify potentially suspicious characteristics in that existing
message and explain how the recipient can stay safe.
You must NOT:
- create a scam
- improve a scam
- write phishing messages
- provide instructions for committing fraud
- suggest ways to make a scam more convincing
You MAY:
- classify the risk of an existing message
- identify suspicious signals
- explain why those signals matter
- identify the action requested by the sender
- recommend safe verification steps
IMPORTANT RULES:
1. ScamLens provides a risk assessment, not a definitive verdict.
2. Never claim that a message is definitely fraudulent.
3. Base your reasoning only on the supplied message and evidence.
4. Never invent information about the sender or organization.
5. Treat individual warning signs as signals, not proof.
6. Consider the combination and context of multiple signals.
7. If evidence is insufficient, clearly state the uncertainty.
8. Do not make absolute claims about what legitimate organizations
   always or never do.
9. Explain the specific evidence found in the message.
10. Give practical steps for independently verifying suspicious requests.
11. Do not help create, improve, or optimize scams.
RISK GUIDANCE:
LOW:
Few or no suspicious signals are present.
MEDIUM:
Some suspicious signals are present, but evidence is not strong
enough to clearly classify the message as high risk.
HIGH:
Multiple significant warning signs appear together, especially when
the message requests money, credentials, sensitive information,
or urgent action.
Return the result using this structure:
RISK:
LOW / MEDIUM / HIGH
SCAM TYPE:
Phishing / Impersonation / Payment scam / KYC-account scam /
Job scam / Prize-reward scam / Investment scam / Other / Unclear
WARNING SIGNS:
- Specific evidence from the message
- Specific evidence from the message
WHAT THE SENDER WANTS:
Describe the action the sender appears to be requesting.
RECOMMENDED ACTION:
Give practical safety advice.
CONFIDENCE:
LOW / MEDIUM / HIGH
"""
# --------------------------------------------------
# 3. Create the Strands Agent
# --------------------------------------------------

agent = Agent(
    model=model,
    system_prompt=SCAMLENS_PROMPT
)


# --------------------------------------------------
# 4. Reliable baseline report
# --------------------------------------------------
def build_baseline_report(message: str, signals: list[str]) -> str:
    """Create a consistent safety report when the local model is unavailable."""
    text = message.lower()
    score = 0

    has_urgency = any(word in text for word in ["urgent", "immediately", "act now", "today", "expires"])
    has_money_request = any(
        word in text
        for word in ["pay", "payment", "send money", "transfer", "fee", "₹", "$", "dollar", "usd", "upi"]
    )
    has_sensitive_request = any(
        word in text
        for word in ["otp", "password", "pin", "cvv", "verification code"]
    )
    has_identity_request = any(
        phrase in text
        for phrase in ["verify your identity", "verify identity", "identity verification", "confirm your identity"]
    )
    has_account_threat = any(
        phrase in text
        for phrase in ["kyc", "account blocked", "account suspended", "verify your account"]
    )
    has_device_alert = any(
        phrase in text
        for phrase in ["new device", "unknown device", "unrecognized device", "new login", "unusual login", "unrecognized login", "suspicious login"]
    )
    has_reward = any(word in text for word in ["winner", "prize", "lottery", "cashback", "congratulations"])
    has_link = "http://" in text or "https://" in text

    if has_urgency:
        score += 1
    if has_money_request:
        score += 2
    if has_sensitive_request:
        score += 3
    if has_identity_request:
        score += 2
    if has_account_threat:
        score += 2
    if has_device_alert:
        score += 2
    if has_reward:
        score += 1
    if has_link:
        score += 1

    # A link plus urgency and a financial or identity request is a high-risk combination.
    if score >= 5 or (has_link and has_urgency and (has_money_request or has_identity_request)):
        risk = "HIGH"
    elif score >= 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    if has_device_alert and has_money_request:
        scam_type = "Account-transfer scam"
    elif has_account_threat:
        scam_type = "KYC-account scam"
    elif has_sensitive_request or has_identity_request:
        scam_type = "Phishing / credential request"
    elif has_reward:
        scam_type = "Prize-reward scam"
    elif has_money_request:
        scam_type = "Payment scam"
    elif score:
        scam_type = "Potentially suspicious message"
    else:
        scam_type = "No clear scam pattern detected"

    requested_actions = []
    if has_account_threat:
        requested_actions.append("complete account verification")
    if has_money_request:
        requested_actions.append("make a payment or money transfer")
    if has_sensitive_request:
        requested_actions.append("share sensitive authentication information")
    if has_identity_request:
        requested_actions.append("verify your identity")
    if has_link:
        requested_actions.append("open a link")

    if requested_actions:
        sender_wants = "The sender appears to want you to " + " and ".join(requested_actions) + "."
    else:
        sender_wants = "No clear high-risk action was detected in the message."

    if risk == "HIGH":
        recommended_action = (
            "Do not click links, send money, or share OTPs or passwords. "
            "Verify the request through the organisation's official app, website, or phone number."
        )
    elif risk == "MEDIUM":
        recommended_action = (
            "Pause before acting and verify the request independently through an official channel. "
            "Do not share sensitive information or make a payment until it is verified."
        )
    else:
        recommended_action = (
            "No strong automated warning signs were found. Still verify unexpected requests "
            "before sharing personal information or making a payment."
        )

    if score >= 5:
        confidence = "HIGH"
    elif score >= 2:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    warning_signs = "\n".join(f"- {signal}" for signal in signals)
    if not warning_signs:
        warning_signs = "- No obvious automated warning signs detected."

    return f"""RISK:
{risk}

SCAM TYPE:
{scam_type}

WARNING SIGNS:
{warning_signs}

WHAT THE SENDER WANTS:
{sender_wants}

RECOMMENDED ACTION:
{recommended_action}

CONFIDENCE:
{confidence}"""


def response_text(response) -> str:
    """Extract text from Strands responses across supported response formats."""
    try:
        content = response.message["content"]
        first_item = content[0]
        if isinstance(first_item, dict):
            return first_item["text"]
        return first_item.text
    except (AttributeError, KeyError, IndexError, TypeError):
        return str(response)


def is_structured_report(result: str) -> bool:
    """Only use model output when it contains every section the UI needs."""
    required_sections = [
        "RISK:",
        "SCAM TYPE:",
        "WARNING SIGNS:",
        "WHAT THE SENDER WANTS:",
        "RECOMMENDED ACTION:",
        "CONFIDENCE:",
    ]
    return all(section in result.upper() for section in required_sections)


def report_risk(result: str) -> str:
    """Read the risk label from a structured ScamLens report."""
    match = re.search(r"(?im)^RISK\s*:\s*(LOW|MEDIUM|HIGH)", result)
    return match.group(1).upper() if match else "LOW"


def risk_rank(risk: str) -> int:
    """Give risk labels an order so model output cannot lower the evidence score."""
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3}.get(risk.upper(), 1)
# --------------------------------------------------
# 5. Analyze a message
# --------------------------------------------------
def analyze_message(message: str):
    # Detect observable evidence using Python
    signals = detect_signals(message)
    baseline_report = build_baseline_report(message, signals)

    # Do not make an obvious high-risk case wait for a local model response.
    # The deterministic evidence already provides a clear, safe report.
    if report_risk(baseline_report) == "HIGH":
        return baseline_report

    if signals:
        evidence = "\n".join(
            f"- {signal}" for signal in signals
        )
    else:
        evidence = "- No obvious automated signals detected."
    # Give the original message AND evidence to the AI
    analysis_prompt = f"""
Analyze the following message for cybersecurity awareness.
MESSAGE:
{message}
DETECTED EVIDENCE:
{evidence}
Use the detected evidence as supporting information,
but use contextual reasoning to interpret the message.
This is a defensive analysis of an existing message.
Do not create or improve any scam.
"""
    try:
        response = agent(analysis_prompt)
        model_result = response_text(response)

        if is_structured_report(model_result) and risk_rank(report_risk(model_result)) >= risk_rank(report_risk(baseline_report)):
            return model_result
    except Exception:
        # The evidence engine still provides a useful result if Ollama is unavailable.
        pass

    return baseline_report
# --------------------------------------------------
# 5. Test ScamLens
# --------------------------------------------------
if __name__ == "__main__":
    test_message = """
    URGENT! Your bank account will be blocked today.
    Complete your KYC immediately by paying ₹499 using this link:
    http://bank-verify-example.com
    """
    result = analyze_message(test_message)
    print("\n========== SCAMLENS ==========\n")
    print(result)
