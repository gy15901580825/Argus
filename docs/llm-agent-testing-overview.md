# LLM / AI Agent / Chatbot Testing Overview

This document offers a visual summary of the testing landscape for LLM, AI Agent, and Chatbot products, mapped to concrete Argus scenarios.

> Rendering note: this document uses Mermaid diagrams. GitHub, VS Code (Markdown Preview Mermaid), Obsidian, and Typora render them out of the box.

---

## 1. Big-Picture Mind Map (8 Testing Dimensions)

```mermaid
mindmap
  root((LLM / Agent<br/>Testing))
    Functional Correctness
      Factual Accuracy / Hallucination Rate
      Task Success
      Tool-Call Correctness
      Instruction Following (IFEval)
      Multi-Turn Consistency
    Quality Evaluation
      LLM-as-a-Judge
      Pairwise / Elo
      Human Eval
      Rubric-Based Scoring
    Robustness & Adversarial
      Prompt Injection
      Jailbreak
      Adversarial Examples
      Out-of-Bounds Inputs
    Safety & Compliance
      Red-Teaming
      Bias & Fairness
      PII / Sensitive Info
      Copyright & Plagiarism
      Content Filtering
    Performance & Cost
      Latency (TTFT / TPS)
      Throughput (QPS)
      Token Cost
      Stability / Error Rate
    Agent-Specific
      Planning
      Long-Horizon Execution
      Environment Interaction (Browser)
      Memory / State
      Tool-Failure Recovery
      Step / Cost Budgets
    Regression & Observability
      Eval-Set Regression
      CI Gating
      A/B Canary
      Tracing
      Model-Drift Detection
    User Experience
      Conversation Flow
      Proactive Clarification
      Refusal Fallback
      Multimodal Consistency
```

---

## 2. Priority Matrix (Launch Risk × Implementation Cost)

```mermaid
quadrantChart
    title Test-item priority (do top-right first, then top-left)
    x-axis "Low cost" --> "High cost"
    y-axis "Low risk" --> "High risk"
    quadrant-1 "Must do (MVP)"
    quadrant-2 "Worth investing"
    quadrant-3 "Consider later"
    quadrant-4 "Add on demand"
    "Prompt Injection defense": [0.3, 0.92]
    "Task success baseline": [0.35, 0.88]
    "PII leak detection": [0.25, 0.85]
    "Token cost monitoring": [0.2, 0.7]
    "LLM-as-a-Judge": [0.4, 0.75]
    "Model-swap regression": [0.45, 0.82]
    "End-to-end tracing": [0.55, 0.78]
    "Jailbreak suite": [0.6, 0.65]
    "Human Eval": [0.85, 0.6]
    "Bias Benchmark": [0.7, 0.4]
    "Multimodal consistency": [0.8, 0.35]
    "Adversarial perturbation": [0.65, 0.3]
```

---

## 3. Where Testing Lives in the Dev Lifecycle (Shift-Left → Shift-Right)

```mermaid
flowchart LR
    subgraph Dev[Development]
        A[Prompt / code change] --> B[Unit eval<br/>quick smoke]
        B --> C[Full eval set<br/>regression baseline]
    end
    subgraph CI[CI gate]
        C --> D{Pass rate<br/>≥ threshold?}
        D -- No --> E[Block merge]
        D -- Yes --> F[Build image]
    end
    subgraph Stage[Staging / Canary]
        F --> G[Canary traffic<br/>A/B compare]
        G --> H{Live metrics<br/>stable?}
        H -- No --> I[Rollback]
        H -- Yes --> J[Full rollout]
    end
    subgraph Prod[Production]
        J --> K[Continuous tracing<br/>Langfuse]
        K --> L[Drift detection /<br/>user feedback]
        L -.feedback.-> A
    end

    style E fill:#fecaca,color:#000
    style I fill:#fecaca,color:#000
    style J fill:#bbf7d0,color:#000
```

---

## 4. Four Evaluation Methods Compared

```mermaid
flowchart TB
    subgraph Methods[Evaluation methods]
        M1["📏 Rule-based<br/>(regex / exact match)"]
        M2["🤖 LLM-as-a-Judge<br/>(stronger model scores)"]
        M3["🆚 Pairwise / Elo<br/>(head-to-head)"]
        M4["👤 Human Eval<br/>(human scoring)"]
    end
    M1 -->|Low cost / narrow coverage| Use1["Structured output<br/>Tool-call arguments"]
    M2 -->|Medium cost / broad coverage| Use2["Open-ended answers<br/>Relevance / helpfulness"]
    M3 -->|Compare old vs new| Use3["Model / prompt selection<br/>A/B"]
    M4 -->|High cost / most authoritative| Use4["Ground truth<br/>Judge calibration"]

    style M1 fill:#dbeafe,color:#000
    style M2 fill:#e9d5ff,color:#000
    style M3 fill:#fed7aa,color:#000
    style M4 fill:#fecaca,color:#000
```

---

## 5. Mapped to the Argus Architecture

```mermaid
flowchart LR
    U[User] --> FE[Frontend<br/>Next.js]
    FE --> API[API Service<br/>:8881]
    API --> ORCH[Orchestrator<br/>:8081]
    ORCH --> CA[Client Agent<br/>browser-use]
    ORCH --> TAPI[testing_api_service<br/>:8000]
    ORCH --> TWUI[testing_web_ui_service<br/>:8002]
    CA --> Target[Target site]
    TAPI --> TR[test-runner]

    T1[[🎯 Task-success baseline<br/>bug-find rate / false-positive rate]] -.-> CA
    T2[[🛡️ Prompt-injection defense<br/>payloads planted on target site]] -.-> CA
    T3[[✅ Generated-script executability<br/>auto-run pytest]] -.-> TAPI
    T4[[📊 Tracing + token cost<br/>Langfuse integration]] -.-> ORCH
    T5[[🔁 Model-swap regression<br/>gpt-5.3 ↔ gemini-3]] -.-> ORCH
    T6[[🔒 PII / output safety<br/>Azure Content Safety]] -.-> API

    style T1 fill:#fef3c7,color:#000
    style T2 fill:#fecaca,color:#000
    style T3 fill:#bbf7d0,color:#000
    style T4 fill:#dbeafe,color:#000
    style T5 fill:#e9d5ff,color:#000
    style T6 fill:#fed7aa,color:#000
```

---

## 6. Argus Roadmap (Suggested Order)

```mermaid
gantt
    title LLM / Agent testing capability buildout
    dateFormat  YYYY-MM-DD
    axisFormat %m-%d
    section P0 Must
    Task-success baseline dataset      :p0a, 2026-04-20, 10d
    Prompt-injection test suite        :p0b, 2026-04-25, 10d
    Generated-script executability     :p0c, 2026-05-01, 7d
    section P1 Important
    Tracing integration (Langfuse)     :p1a, 2026-05-05, 7d
    Token-cost dashboard               :p1b, 2026-05-10, 5d
    LLM-as-a-Judge scoring             :p1c, 2026-05-12, 10d
    section P2 Advanced
    Model-swap regression CI           :p2a, 2026-05-20, 7d
    Jailbreak / adversarial examples   :p2b, 2026-05-25, 10d
    A/B canary (per subscription tier) :p2c, 2026-06-01, 10d
    section P3 Polish
    Human Eval workflow                :p3a, 2026-06-10, 14d
    Bias / Fairness baseline           :p3b, 2026-06-20, 10d
```

---

## 7. Toolchain Quick-Reference

| Category | Recommended Tools | When to Use |
|---|---|---|
| Eval framework | **Promptfoo** / DeepEval / OpenAI Evals | Regression in CI |
| RAG-specific | **Ragas** | Retrieval-augmented scenarios (document QA) |
| Benchmark datasets | **WebArena** / AgentBench / MT-Bench | Compare against academic / public baselines |
| Red-Team | **Garak** / PyRIT / Giskard | Jailbreak and prompt-injection scanning |
| Observability | **Langfuse** / Arize Phoenix | Production tracing: cost / latency / quality |
| Guardrails | **LlamaGuard** / NeMo Guardrails | Input / output content filtering |
| Agent eval | **smithery.ai/agentic-eval** / supercent skill | Task-level agent evaluation |

---

## 8. The One-Page Mantra

> **"Functionally accurate, quality measurable, adversary-resistant, safe and compliant, performance testable, agent plans well, regression gated, experience smooth."**

Eight phrases, eight dimensions — a pre-launch self-check across them covers about 90% of the testing risk for an LLM product.

---

## 9. The Most Urgent Market Needs (Ranked by Urgency)

```mermaid
flowchart TB
    R1["🥇 #1 Agent Evaluation<br/>(long-horizon task success / tool-call correctness)"] --> R1d["State: plenty of academic benchmarks (WebArena/SWE-Bench), few production-grade frameworks<br/>Pain: in-house eval builds take 3–6 months on average, hard to reuse"]
    R2["🥈 #2 Production Observability<br/>(Tracing + cost + quality drift)"] --> R2d["State: Langfuse/Phoenix are rising, but penetration is <20%<br/>Pain: most teams still glue together logs + Grafana"]
    R3["🥉 #3 Prompt Injection / AI Security"] --> R3d["State: OWASP LLM Top 10 only stabilized in 2024<br/>Pain: once agents call tools, almost no commercial defense for indirect injection"]
    R4["#4 Regression CI for Prompt/Model"] --> R4d["State: Promptfoo is gaining traction, but CI integration is DIY<br/>Pain: vendors silently swap model versions → silent quality regressions"]
    R5["#5 Human Eval at Scale"] --> R5d["State: Scale AI / Surge / Invisible are expensive and slow<br/>Pain: SMBs can't afford it; LLM-Judge isn't accurate enough"]
    R6["#6 Multi-Agent / Tool-Use Evaluation"] --> R6d["State: nearly empty, mostly the AgentBench academic benchmark<br/>Pain: no industry baseline for production-agent reliability"]

    style R1 fill:#fecaca,color:#000
    style R2 fill:#fed7aa,color:#000
    style R3 fill:#fef3c7,color:#000
```

**The two biggest gaps:**

- **Agent-level (not LLM-level) eval standards** — the LLM layer has MMLU/HELM; the agent layer has no commonly accepted benchmark.
- **Security testing where the subject is an Agent** — existing tools assume the subject is a "chat model", not an agent that calls tools and drives browsers.

---

## 10. Most-Trusted Products (by Tier)

```mermaid
flowchart LR
    subgraph Tier1["🏆 Tier 1 (de facto industry standards)"]
        T1a["Langfuse<br/>OSS tracing leader<br/>⭐9k / YC W23"]
        T1b["LangSmith<br/>Official LangChain<br/>Wide enterprise adoption"]
        T1c["Promptfoo<br/>Most active OSS eval community<br/>⭐6k+"]
    end
    subgraph Tier2["🥈 Tier 2 (dominant in niches)"]
        T2a["Braintrust<br/>Eval platform, used by Stripe/Notion<br/>$36M raised"]
        T2b["Arize Phoenix<br/>Observability + RAG<br/>Enterprise-friendly"]
        T2c["Humanloop<br/>Prompt management + Eval<br/>Duolingo/Gusto"]
    end
    subgraph Tier3["🥉 Tier 3 (strong in their vertical)"]
        T3a["Lakera Guard<br/>Prompt-injection defense<br/>Dropbox/Citi"]
        T3b["Patronus AI<br/>Safety eval<br/>$17M raised"]
        T3c["Galileo<br/>Enterprise LLM evaluation"]
        T3d["DeepEval<br/>pytest-style OSS<br/>⭐4k+"]
    end
    subgraph Tier4["🔬 Emerging / Agent-focused"]
        T4a["smithery.ai<br/>MCP/Agent eval"]
        T4b["Freeplay<br/>Prompt + eval collaboration"]
        T4c["Giskard<br/>ML + LLM testing"]
        T4d["Garak<br/>NVIDIA OSS red-team"]
    end

    Tier1 --> Tier2 --> Tier3 --> Tier4
```

---

## 11. Overall Recommendation Order (by Argus Urgency)

| Order | Capability | First Choice | Rationale |
|---|---|---|---|
| **1** | Tracing / observability | **Langfuse** (self-hosted) | Free OSS, compatible with R2, no lock-in; without it, everything downstream is blind |
| **2** | Eval CI | **Promptfoo** | OSS, YAML-configured, CI-friendly; regression across gpt-5.3 ↔ gemini-3 swaps |
| **3** | Prompt Injection | **Lakera Guard** + **Garak** red-team | Lakera as runtime gateway, Garak for offline scanning |
| **4** | Agent task success | **Build in-house** + borrow from WebArena | No mature product exists; Argus's business is squarely in this space |
| **5** | Safety / Bias | Defer Patronus / Galileo | Lower priority; Azure Content Safety as initial fallback |

---

## 12. Strategic Takeaways for Argus

1. **The biggest commercial opportunity sits at the intersection of #1 and #6** — "Agent task-success baselines" + "Web UI Agent reliability testing". Langfuse owns tracing, Promptfoo owns LLM eval, **but no one is solving "I'll test whether your Agent can actually complete your business workflows"**. Argus's ClientWebUIAgent can be reframed as **"Agent Reliability Testing as a Service"**.

2. **Langfuse is the first thing to integrate** — the self-hosted version. Within two days you can add tracing to Orchestrator + the testing_* services, immediately see token cost and latency distributions, and capture the highest ROI.

3. **Don't rush to buy Lakera** — first run a baseline with open-source Garak, see how the agent holds up against injection, then decide whether a commercial option is warranted.

