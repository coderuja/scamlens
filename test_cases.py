from scamlens import analyze_message
test_cases = [
    {
        "name": "Obvious KYC phishing",
        "message": """
        URGENT! Your bank account will be blocked today.
        Complete your KYC immediately by paying ₹499 using this link:
        http://bank-verify-example.com
        """
    },

    {
        "name": "Fake job offer",
        "message": """
        Congratulations! You have been selected for an Amazon work
        from home job. Pay ₹1,999 registration fee today to confirm
        your position. Send the payment to this UPI ID immediately.
        """
    },

    {
        "name": "Potentially legitimate bill reminder",
        "message": """
        Your electricity bill of ₹842 is due on September 25.
        Please pay using the official electricity board website
        or mobile application.
        """
    },

    {
        "name": "Ambiguous account message",
        "message": """
        Your account details need to be updated.
        Please contact customer support for assistance.
        """
    },

    {
        "name": "Prize scam",
        "message": """
        Congratulations! You have won ₹50,000 in our special
        customer reward program. Pay ₹999 processing charges
        to claim your prize today.
        """
    }
]
for test in test_cases:
    print("\n" + "=" * 70)
    print(test["name"])
    print("=" * 70)
    print("\nMESSAGE:")
    print(test["message"].strip())
    print("\nSCAMLENS ANALYSIS:\n")
    result = analyze_message(test["message"])
    print(result)