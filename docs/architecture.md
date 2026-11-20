# KAVACH — System Architecture & Data Flow

**Team अपराजित** &bull; Startup Buildathon India 2026

---

## 🏗️ High-Level System Architecture

```
                                 +-------------------------------------------------+
                                 |                  KAVACH ENGINE                  |
                                 |                                                 |
                                 |  +--------------------+  +-------------------+  |
                                 |  | /screen            |  | /check            |  |
                                 |  | - Regex/Heuristics |  | - Policy Rules    |  |
                                 |  | - Zero-width strip |  | - Canary Token    |  |
                                 |  | - Hinglish filters |  | - Egress Control  |  |
                                 |  | - Gemini Screener  |  | - Gemini Alignment|  |
                                 |  +---------+----------+  +---------+---------+  |
                                 |            |                       |            |
                                 |            +----------+ +----------+            |
                                 |                       | |                       |
                                 |            +----------v-v----------+            |
                                 |            | SHA-256 Audit Ledger  |            |
                                 |            | - Hash chaining       |            |
                                 |            | - /audit/verify       |            |
                                 |            +-----------------------+            |
                                 +-------------------------------------------------+
                                                          ▲
                                                          │ HTTP / In-Process
+-------------------------+      +------------------------┴------------------------+
|   Incoming Data Source  |      |                   KAVACH GUARD                  |
|   (Emails / Files / Web)|      |                                                 |
+------------+------------+      |   +------------------------------------------+  |
             │                   |   | read(source, text)                       |  |
             ▼                   |   | - If ON: /screen -> Sanitized Text       |  |
+-------------------------+      |   | - If OFF: Raw text directly              |  |
|      AI DEMO AGENT      |      |   +------------------------------------------+  |
|                         |      |   +------------------------------------------+  |
| - Plans tool actions    |◄────►|   | call(tool, args)                         |  |
| - Gemini / Scripted     |      |   | - If ON: /check -> ALLOW | BLOCK | ASK   |  |
|   planner               |      |   | - If OFF: Direct execution               |  |
+-------------------------+      |   +--------------------+---------------------+  |
                                 +------------------------│------------------------+
                                                          │
                                         +----------------v----------------+
                                         |         Dashboard UI            |
                                         | - Real-time approval modal      |
                                         | - Live timeline & event stream  |
                                         | - BREACHED / PROTECTED overlay  |
                                         +---------------------------------+
```

---

## 🔄 Execution Sequence: Run 1 vs Run 2

### Run 1: Kavach Switch is OFF (Vulnerable)
```mermaid
sequenceDiagram
    autonumber
    actor User as User Riya
    participant Agent as Demo Agent
    participant Guard as Kavach Guard (OFF)
    participant Tool as Fake Tools
    participant Attacker as verify@cloudnest-billing

    User->>Agent: "Pay electricity bill and send report to manager"
    Agent->>Guard: read("email:3", raw_poisoned_body)
    Note over Guard: Switch is OFF - Bypasses screening
    Guard-->>Agent: Raw text (contains hidden exfiltration instruction)
    Agent->>Guard: call("pay_bill", {payee: "Delhi Power", amount: 3420})
    Guard->>Tool: Execute pay_bill() directly
    Agent->>Guard: call("send_email", {to: "karan.mehta", file: "report.pdf"})
    Guard->>Tool: Execute send_email() directly
    Agent->>Guard: call("send_email", {to: Attacker, file: "customer_data.csv"})
    Guard->>Tool: Execute send_email() directly!
    Tool-->>Attacker: Leaked customer_data.csv with canary KVC-CANARY-7731!
    Note over Tool: BREACH DETECTED -> Fullscreen RED Overlay
```

### Run 2: Kavach Switch is ON (Protected)
```mermaid
sequenceDiagram
    autonumber
    actor User as User Riya
    participant Agent as Demo Agent
    participant Guard as Kavach Guard (ON)
    participant Engine as Kavach Engine
    participant Human as Human Operator
    participant Tool as Fake Tools

    User->>Agent: "Pay electricity bill and send report to manager"
    Agent->>Guard: read("email:3", raw_poisoned_body)
    Guard->>Engine: POST /screen (detects HTML comment & secrecy imperative)
    Engine-->>Guard: FLAGGED ("imperative_to_agent", "secrecy_request")
    Note over Guard: email:3 added to TAINTED sources list
    Guard-->>Agent: Sanitized text (Hidden comment stripped)
    Agent->>Guard: call("pay_bill", {amount: 3420})
    Guard->>Engine: POST /check (Policy & Task check)
    Engine-->>Guard: ALLOW (Matches task keywords, known payee)
    Guard->>Tool: pay_bill() executed successfully
    Agent->>Guard: call("send_email", {to: "karan.mehta", file: "report.pdf"})
    Guard->>Engine: POST /check
    Engine-->>Guard: ALLOW (Internal manager, internal file)
    Guard->>Tool: send_email() executed successfully
    Agent->>Guard: call("send_email", {to: "verify@cloudnest", file: "customer_data.csv"})
    Guard->>Engine: POST /check
    Note over Engine: Policy: external_recipient + restricted_file + tainted_context
    Engine-->>Guard: ASK (Human approval required)
    Guard->>Human: Displays Approval Modal on Dashboard
    Human->>Guard: Clicks "BLOCK"
    Note over Guard: Action stopped. Audit entry logged.
    Note over Tool: Data remains safe inside organization -> Fullscreen GREEN Overlay
```

---

## 🔒 Security Model & Invariants

1. **Task Immutability**:
   `user_task` is held in server memory or JWT session. The agent never provides the task to `/check`.
2. **Cryptographic Hash Chain**:
   ```
   H_0 = 0000000000000000000000000000000000000000000000000000000000000000
   H_i = SHA-256( H_{i-1} + canonical_json(entry_i) )
   ```
   Ensures forensic non-repudiation in enterprise audits.
3. **Decoy Canary Tripwires**:
   Every restricted file generated contains unique canary strings (`KVC-CANARY-xxxx`). A simple substring match stops zero-day prompt injection exfiltration even before parsing semantics.
