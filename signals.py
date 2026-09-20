import re
from urllib.parse import urlparse
def detect_signals(message: str) -> list[str]:
    """
    Detect observable scam-related signals in a message.

    This function does not decide whether a message is a scam.
    It only extracts evidence that the AI can reason about.
    """
    signals = []
    text = message.lower()
    # Urgency
    urgency_words = [
        "urgent",
        "immediately",
        "act now",
        "within",
        "today",
        "last warning",
        "expires",
        "final notice",
    ]
    if any(word in text for word in urgency_words):
        signals.append(
            "Urgency or time-pressure language detected.")
    # Payment request
    payment_words = [
        "pay",
        "payment",
        "send money",
        "transfer",
        "fee",
        "₹",
        "$",
        "dollar",
        "usd",
        "upi",
    ]
    if any(word in text for word in payment_words):
        signals.append("A payment or money-transfer request is present.")
    # OTP / credentials
    sensitive_words = [
        "otp",
        "password",
        "pin",
        "cvv",
        "verification code",
    ]
    if any(word in text for word in sensitive_words):
        signals.append("The message references sensitive authentication information.")
    # Identity verification requests
    identity_words = [
        "verify your identity",
        "verify identity",
        "identity verification",
        "confirm your identity",
    ]
    if any(word in text for word in identity_words):
        signals.append("The message asks the recipient to verify their identity.")
    # KYC / account threats
    account_words = [
        "kyc",
        "account blocked",
        "account suspended",
        "account will be closed",
        "verify your account",
    ]
    if any(word in text for word in account_words):
        signals.append("Account verification or account-blocking language detected.")
    # Unexpected-device or login alerts
    device_words = [
        "new device",
        "unknown device",
        "unrecognized device",
        "new login",
        "unusual login",
        "unrecognized login",
        "suspicious login",
    ]
    if any(word in text for word in device_words):
        signals.append("An unfamiliar-device or unexpected-login alert is mentioned.")
    # Reward / prize
    reward_words = [
        "winner",
        "won",
        "prize",
        "reward",
        "lottery",
        "cashback",
        "congratulations",
    ]
    if any(word in text for word in reward_words):
        signals.append(
            "Unexpected reward, prize, or financial benefit is mentioned.")
    # URLs
    urls = re.findall(
        r"https?://[^\s]+",message)
    if urls:
        signals.append(
            f"{len(urls)} URL(s) detected in the message.")
        for url in urls:
            try:
                domain = urlparse(url).netloc
                if domain:
                    signals.append(
                        f"Link domain detected: {domain}" )
            except Exception:
                pass
    # Phone number
    phone_pattern = r"(?<!\d)(?:\+91[-\s]?)?[6-9]\d{9}(?!\d)"
    if re.search(phone_pattern, message):
        signals.append(
            "A phone number is present in the message.")
    return signals

if __name__ == "__main__":

    test_message = """
    URGENT! Your bank account will be blocked today.
    Complete your KYC immediately by paying ₹499 using this link:
    http://bank-verify-example.com
    """

    detected = detect_signals(test_message)

    print("Detected signals:")

    for signal in detected:
        print("-", signal)
