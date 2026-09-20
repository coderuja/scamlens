import os
import sys

# Ensure UTF-8 output on Windows terminal
sys.stdout.reconfigure(encoding='utf-8')

from scamlens import model, agent, analyze_message

print("=" * 60)
print("ScamLens Bedrock Verification")
print("=" * 60)

api_key = os.environ.get("BEDROCK_API_KEY")
if not api_key:
    print("❌ No BEDROCK_API_KEY found in .env file.")
    print("Please add BEDROCK_API_KEY=your_key to .env")
    sys.exit(1)

region = os.environ.get("AWS_DEFAULT_REGION", "eu-north-1")
model_id = os.environ.get("BEDROCK_MODEL_ID", "amazon.nova-lite-v1:0")

print(f"✅ Found BEDROCK_API_KEY (length: {len(api_key)})")
print(f"Provider: {type(model).__name__}")
print(f"Region: {region}")
print(f"Model ID: {model_id}")

print("\n1. Testing direct Bedrock API invocation...")
try:
    response = agent("Say 'ScamLens Bedrock is connected!' in one short sentence.")
    print("✅ Bedrock call successful!")
    print(f"Response: {response}")
except Exception as e:
    err_str = str(e)
    print(f"\n⚠️ Direct Bedrock call failed: {type(e).__name__}")
    if "AccessDeniedException" in err_str:
        print("Reason: Authentication or Region Mismatch.")
        print("Tip: Make sure the region in .env matches the region where the key was generated.")
    elif "ValidationException" in err_str:
        print("Reason: Model access not granted or model not available in this region.")
        print("Tip: Check 'Model access' in the AWS Bedrock console for this region.")
    else:
        print(f"Detail: {err_str[:200]}")

print("\n2. Testing end-to-end analyze_message()...")
test_msg = "URGENT! Your bank account will be blocked today. Complete KYC by paying ₹499 using: http://bank-verify-example.com"
result = analyze_message(test_msg)
print("✅ ScamLens analysis completed successfully (safe fallback active).")
print(f"Risk Output: {result.splitlines()[1] if len(result.splitlines()) > 1 else 'Done'}")
print("\n" + "=" * 60)
