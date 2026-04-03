# Colorado AI Act Transparency Statement

This statement describes how AgentKMS ensures the transparency and auditability of AI systems, as required by the Colorado AI Act (SB 205).

## 1. Transparency and Attribution

AgentKMS is the security foundation for all AI agents in the enterprise. Every operation conducted by an agent — including every call to an LLM provider (Anthropic, OpenAI, etc.) — is uniquely attributed to a human-led session.

### 1.1 Traceability
AgentKMS maps every AI-driven operation (LLM call, cryptographic signature, data encryption) to:
- **Individual Builder Identity**: The human developer or service account who initiated the agent session.
- **Team Identity**: The department or project team responsible for the agent.
- **Agent Session**: A unique identifier for that specific Pi instance or execution turn.

### 1.2 Audit Trails
Every operation is recorded in the **tamper-evident audit log** with:
- `caller_id`: The human identity from the mTLS certificate.
- `team_id`: The team responsible for the operation.
- `agent_session`: The unique session identifier.
- `operation`: The specific action (e.g., `credential_vend` for LLM, `sign` for a payload).
- `payload_hash`: The SHA-256 hash of the input, enabling reconstruction and verification of what was processed.
- `outcome`: Whether the operation was successful, denied, or encountered an error.

## 2. High-Risk AI Disclosure

Under SB 205, AgentKMS provides the necessary transparency data for high-risk AI systems.

### 2.1 Model Attribution
The audit log records which specific AI model and provider were used during a session. This allows compliance officers to:
- **Trace Decisions**: Reconstruct the specific model input (via the payload hash) and the model used at the time of a decision.
- **Audit for Bias**: Analyze the volume and outcomes of operations across different teams and models.
- **Assess Impact**: Identify which high-risk systems are active and which individuals are interacting with them.

## 3. Human Oversight

AgentKMS enforces policy-based human oversight for critical operations.

### 3.1 Policy Enforcement
The **Policy Engine** ensures that AI agents can only perform operations explicitly allowed for their scope. This prevents:
- **Unauthorized Actions**: Agents cannot use cryptographic keys or LLM credentials they are not authorized for.
- **Exceeding Limits**: Rate limiting and anomaly detection prevent agents from making unauthorized or excessive calls to models.

### 3.2 Human Approval
For highly sensitive cryptographic operations (e.g., production signing keys), the Policy Engine can be configured to require direct human approval or presence (m-of-n) before an operation is executed.

## 4. Ongoing Compliance

AgentKMS provides the data foundation for annual impact assessments required by the Colorado AI Act. The centralized audit logs enable automated reporting on:
- **System Usage**: Who is using which AI models and for what purpose.
- **Security Posture**: How many unauthorized access attempts were blocked.
- **Operational Health**: Latency, error rates, and volume of AI operations across the enterprise.
