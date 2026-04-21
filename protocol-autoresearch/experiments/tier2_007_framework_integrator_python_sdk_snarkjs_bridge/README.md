# Python SDK with native snarkjs bridge for LangChain/CrewAI

Ship a `bolyra` PyPI package that wraps snarkjs via a lightweight Node subprocess or WASM bridge, exposing `enroll_agent()`, `prove_handshake()`, `verify_handshake()`, and `delegate()` as sync/async Python callables. The SDK must return Pydantic models so LangChain's structured output parsing and CrewAI's task results can consume proof artifacts directly. Without this, every Python agent framework user has to hand-roll subprocess calls to snarkjs and parse JSON outputs manually — a dealbreaker for adoption.

## Status

Placeholder — awaiting implementation.
