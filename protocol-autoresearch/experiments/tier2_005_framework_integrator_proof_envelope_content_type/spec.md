# Standard proof envelope with application/bolyra+json content type

## Abstract

Framework integrations all need to serialize/deserialize proof payloads, but each will invent its own format without a standard envelope. Define a JSON schema for BolyraProofEnvelope: {version, circuit, publicSignals[], proof{pi_a, pi_b, pi_c}, metadata{prover, timestamp, chainId}}. Register application/bolyra+json as the content type. All SDK methods (TS and Python) should accept and return this envelope. This prevents every framework adapter from reinventing serialization and makes proofs portable across LangChain↔CrewAI↔AutoGen pipelines.

## Normative Requirements

Implementations MUST ...
