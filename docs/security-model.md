# Odin Security Model — Zero Trust for AI Agents

## 1. Threat Model

Traditional AI agents operate with implicit trust: tool outputs are consumed directly, peer agents are assumed honest, and prompt injection can hijack the entire system. Odin addresses these threats through a layered defense model.

### Attack Surface

| Threat | Vector | Odin Mitigation |
|--------|--------|-----------------|
| **Prompt Injection** | Malicious instructions in user input or tool output | Dual-LLM architecture (CaMeL) — security controls run on a separate privileged model |
| **Tool Output Poisoning** | Compromised tool returns malicious data | IFC taint tracking — tool outputs are labeled UNTRUSTED by default |
| **Privilege Escalation** | Agent gains unauthorized capabilities | 3-ring sandbox model + Cedar policy engine |
| **Identity Spoofing** | Agent impersonates another agent | Ed25519 DID with signed messages |
| **Data Exfiltration** | Sensitive data leaks through tool calls | Confidentiality lattice (PUBLIC < SENSITIVE < SECRET) |
| **Supply Chain Attack** | Malicious skills/MCP servers | AgentLayers scanning + SLSA compliance |
| **Peer Agent Attack** | Unreliable or malicious peer agents | 5-state circuit breaker + trust score verification |

## 2. Dual-LLM Architecture (CaMeL)

Odin implements the CaMeL (CApabilities for Machine Learning) security model from Microsoft Research, adapted for Zero Trust:

```
                    ┌──────────────────────┐
                    │   Privileged Model    │ ← Plans tool calls
                    │  (Full context, tools)│ ← Evaluates security
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │  Quarantined Model    │ ← Processes untrusted data
                    │  (Restricted context) │ ← No tool access
                    └──────────────────────┘
```

The **privileged model** sees the full conversation and plans tool calls. The **quarantined model** only processes data that has been taint-labeled, and it cannot invoke tools directly. This prevents prompt injection from hijacking tool execution.

## 3. Information Flow Control (IFC)

### Integrity Lattice

```
TRUSTED  ──→  DERIVED  ──→  UNTRUSTED
  (User input)   (Computed)    (External data)
```

**Rule**: When data from multiple sources is combined, the output inherits the **lowest integrity**. A TRUSTED user message combined with UNTRUSTED API data produces UNTRUSTED output.

### Confidentiality Lattice

```
PUBLIC  ──→  SENSITIVE  ──→  SECRET
```

**Rule**: When data from multiple sources is combined, the output inherits the **highest confidentiality**. Public data combined with SECRET data becomes SECRET.

### Taint Labels

Every piece of data in Odin carries a `TaintLabel`:

```typescript
interface TaintLabel {
  integrity: 'TRUSTED' | 'DERIVED' | 'UNTRUSTED';
  confidentiality: 'PUBLIC' | 'SENSITIVE' | 'SECRET';
  source: string;        // e.g., "user:direct", "sandbox:ring0:web_search"
  timestamp: number;
}
```

### Tool Call Validation

Before executing any tool, the IFC engine checks:
1. Input integrity >= tool's required integrity level
2. Confidentiality level is compatible with the tool's scope
3. Violations are recorded and count toward trust score degradation

## 4. Sandbox Rings

```
┌─────────────────────────────────────────────────────┐
│                    Ring 2                             │
│   Full access, network, file write                   │
│   Requires: signed + audited skill, human approval   │
│   Timeout: 60s, Memory: 512MB                        │
│  ┌─────────────────────────────────────────────────┐ │
│  │                  Ring 1                          │ │
│  │   Read/write limited, controlled network         │ │
│  │   Requires: scanned SAFE by AgentLayers          │ │
│  │   Timeout: 30s, Memory: 256MB                    │ │
│  │  ┌─────────────────────────────────────────────┐ │ │
│  │  │                Ring 0                       │ │ │
│  │  │   Read-only, no network                     │ │ │
│  │  │   Default for untrusted/unsigned tools      │ │ │
│  │  │   Timeout: 5s, Memory: 64MB                 │ │ │
│  │  └─────────────────────────────────────────────┘ │ │
│  └─────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

Output taint per ring:
- **Ring 0**: Output is always UNTRUSTED
- **Ring 1**: Output is UNTRUSTED (external data)
- **Ring 2**: Output inherits input integrity (trusted environment)

## 5. Policy Engine (Cedar-inspired)

Odin's policy engine evaluates access control decisions in sub-millisecond time using a Cedar-inspired rule system.

### Policy Context

```typescript
interface PolicyContext {
  agentDid: string;       // Who is making the request
  action: string;         // What they want to do (e.g., "tool.invoke")
  resource: string;       // Target resource (e.g., "shell_exec")
  trustScore: number;     // Current trust score (0-100)
  sessionTtl: number;     // Remaining session time
  dailyCalls: number;     // How many calls today
  humanApproval: boolean; // Was this human-approved?
  ring: SandboxRing;      // Execution ring
  taintLabel: TaintLabel; // Input data taint
}
```

### Default Policies

1. **Trust Score Gate**: Block if `trustScore < 40`
2. **Rate Limit**: Block if `dailyCalls > 1000`
3. **Ring 2 Requires Approval**: Block Ring 2 tools without `humanApproval`
4. **Session Expiry**: Block if session TTL has elapsed

### Approval Persistence

Three modes to avoid repetitive human approval:
- `once`: Consumed after first check
- `session`: Persists until session reset
- `always`: Survives session resets (for trusted tools)

## 6. Decentralized Identity (DID)

Every Odin instance generates a unique identity at first launch:

```
did:odin:a1b2c3d4e5f6...  (Ed25519 fingerprint)
```

### DID Document (W3C Compliant)

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
  "id": "did:odin:a1b2c3d4e5f6...",
  "verificationMethod": [{
    "id": "did:odin:a1b2c3d4e5f6...#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:odin:a1b2c3d4e5f6...",
    "publicKeyBase64": "..."
  }],
  "authentication": ["did:odin:a1b2c3d4e5f6...#key-1"],
  "capabilities": [],
  "trustScore": 75.5
}
```

### Ephemeral Credentials

For task delegation (A2A), Odin issues **Intent-Scoped Ephemeral Credentials**:

```typescript
interface EphemeralCredential {
  id: string;           // Unique credential ID
  agentDid: string;     // Issuer DID
  scope: string[];      // Allowed operations (e.g., ["web_search", "memory_read"])
  issuedAt: number;     // Issue timestamp
  expiresAt: number;    // Expiry (TTL-based)
  signature: string;    // Ed25519 signature of the credential data
}
```

These credentials:
- Cannot be reused across tasks
- Expire automatically (time-limited)
- Are cryptographically signed
- Are revocable before expiry

## 7. Trust Score Computation

Trust is a continuous, multi-dimensional metric — not a binary yes/no:

```
Trust Score = Weighted Average of:
  ├── Performance (30%)    ← Success rate of tool executions
  ├── Transparency (15%)   ← Audit log completeness, decision tracing
  ├── Security (25%)       ← IFC violation count, sandbox escape attempts
  ├── Compliance (15%)     ← EU AI Act, OWASP ASI, Singapore MGF, SLSA
  ├── Reputation (10%)     ← AgentLayers network rating
  └── Reliability (5%)     ← Uptime percentage
```

Trust decays over time (configurable half-life, default 7 days) — stale trust is not permanent trust.

## 8. Circuit Breaker (5-State Innovation)

Traditional circuit breakers have 3 states. Odin adds a **DEGRADED** state for graceful partial functionality:

```
CLOSED ──(failures >= degradedThreshold)──→ DEGRADED
DEGRADED ──(failures >= failureThreshold)──→ OPEN
OPEN ──(recovery timeout elapsed)──→ HALF_OPEN
HALF_OPEN ──(2 consecutive successes)──→ CLOSED
HALF_OPEN ──(any failure)──→ OPEN
DEGRADED ──(consecutive successes >= threshold)──→ CLOSED
```

Innovation: **Semantic failure detection** — a 200 OK response that contains hallucinated content is detected via a semantic validator and counts as a double failure.

## 9. Compliance Framework

| Standard | Coverage | Metric |
|----------|----------|--------|
| **EU AI Act** | Transparency, human oversight, risk management | % compliance score |
| **OWASP ASI** | Top 10 AI security risks | Count of mitigated risks |
| **Singapore MGF** | Model Governance Framework | % alignment score |
| **SLSA** | Supply-chain Levels for Software Artifacts | Level 0-4 |

## 10. Security Decision Pipeline

Every tool call passes through 6 security layers before execution:

```
1. Tool Profile Check    → Is this tool in the allowed profile?
2. Loop Detection        → Is this a suspicious repeated call?
3. Approval Check        → Does this require human approval?
4. IFC Validation        → Is the input integrity sufficient?
5. Cedar Policy          → Does policy allow this action?
6. Sandbox Execution     → Execute in the appropriate ring
```

Each decision is recorded in the Decision Trace with:
- Timestamp
- Decision type (ALLOW / WARN / BLOCK)
- Emitter (which layer made the decision)
- Action and detail
- Security layer name
