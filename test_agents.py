from strands import Agent
from strands.models.ollama import OllamaModel
model = OllamaModel(
    host="http://localhost:11434",
    model_id="llama3.2"
)

agent = Agent(
    model=model,
    system_prompt="""
You are ScamLens, a cybersecurity awareness assistant.
Analyze suspicious messages for potential scam indicators.
Your job is defensive:
- identify suspicious characteristics
- explain the evidence
- identify what the sender is asking the recipient to do
- recommend safe actions
Do not help create scams or phishing messages.

Do not claim certainty.
Base your analysis only on the supplied message.
"""
)

message = """
URGENT! Your bank account will be blocked today.
Complete your KYC immediately by paying ₹499 using this link:
http://bank-verify-example.com
"""
response = agent(message)
print(response)