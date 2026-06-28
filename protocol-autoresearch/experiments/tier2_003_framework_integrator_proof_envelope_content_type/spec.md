# Standardized proof envelope with application/bolyra+json content type

## Abstract

Define a canonical JSON envelope format for Bolyra proofs that framework integrations can rely on: `{"version": "1.0", "circuit": "AgentPolicy|Delegation|HumanUniqueness", "proof": {...}, "publicSignals": [...], "metadata": {"provingSystem": "groth16", "timestamp": ...}}`. Register `application/bolyra+json` as the content type. LangChain tool outputs, CrewAI task results, and AutoGen message payloads all need a consistent serialization to pass proofs between agents. Without this, each integration invents its own format and interop breaks. Add schema validation to both SDKs via `validateProofEnvelope()` and include 10+ test vectors in `spec/test-vectors/`.

## Normative Requirements

Implementations MUST ...
