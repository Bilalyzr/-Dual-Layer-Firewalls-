# Product Requirements Document (PRD)
**Project Name:** Unified Dual-Layer AI Firewall & Behavioral Zero-Trust Platform
**Version:** 2.0 | **Status:** Draft for Review

> Reference document extracted from the original `Product Requirements Document.docx`. This MVP implements **Tier 1 (Phase 1–3)** of the rollout.

## 1. Executive Summary
As enterprises rapidly integrate LLMs and autonomous AI agents into web applications, traditional WAFs are becoming inadequate for this new attack surface. Legacy WAFs inspect syntactic structures but are blind to semantic, text-based manipulations like Indirect Prompt Injection. This project delivers a **Unified Dual-Layer AI Firewall and Behavioral Biometrics Platform**: a secure proxy layer that intercepts and analyzes natural-language inputs for jailbreak patterns, while continuously authenticating users via Keystroke Dynamics.

## 2. Problem Statement & Objectives
- **Semantic Attack Surface** — Indirect prompt injection via untrusted content (CamoLeak, CVE-2025-59145).
- **Excessive Agency** — Autonomous agents become high-speed insider threats when compromised.
- **Identity Compromise** — Deepfake-assisted session takeover bypasses static MFA.

**Objectives:** Semantic AI firewall proxy · Reader/Actor privilege separation · Continuous keystroke-dynamics authentication.

## 4. Unified System Architecture
| Stack Layer | Technology | Role |
|---|---|---|
| Client Layer | React JS | Dashboard; captures keydown/keyup via `performance.now()` |
| Proxy Layer | Node.js | API gateway; regex/schema validation; routes prompts; batches telemetry |
| Processing Layer | Python (scikit-learn / PyTorch / LangGraph) | Text vectorization & jailbreak classification; biometric scoring |
| Database Layer | MongoDB | Security alerts, threat taxonomies, "typing DNA" baselines |

## 5. Functional Requirements (Tier 1 subset)
- **1.1** Inbound prompt interception · **1.2** Regex heuristic validation · **1.3** ML text classification w/ tunable threshold · **1.4** Output integrity check · **1.5** Adversarial monitoring (confidence logging + low-confidence sampling)
- **3.1** Keystroke telemetry capture (dwell/flight) · **3.6** Cold-start baseline fallback
- **4.1** Real-time threat feed (OWASP LLM Top 10) · **4.2** Biometric trust scores · **4.3** Agent audit trail

## 6. Non-Functional Requirements
Proxy heuristic latency target < 5ms · biometric scoring low single-digit ms · AES-256 at rest · TLS 1.3 in transit.

## 7. Implementation Strategy
- **Tier 1 (MVP/PoC)** — Node proxy + scikit-learn filter + rolling-average keystroke baseline, single Docker container. *Produces real benchmark data.*
- **Tier 2** — Distributed microservices, LangGraph agents, LSTM+ensemble+SHAP.

> Full text in §5–9 of the original PRD. Tier 2 items (LSTM/SHAP/Trifecta agents) are out of scope for this MVP and surfaced as placeholder panels in the dashboard.
