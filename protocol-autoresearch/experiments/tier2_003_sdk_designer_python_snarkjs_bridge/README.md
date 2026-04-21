# Python SDK with async snarkjs subprocess bridge

Implement the bolyra PyPI package specified in tier2_007 outline: a Node.js subprocess bridge (stdin/JSON/stdout) wrapped in Pydantic v2 models with both sync and async APIs. The target audience is LangChain/CrewAI developers who need `bolyra.prove_handshake()` and `bolyra.delegate()` in Python without touching Node directly. Ship with a bundled node_bridge/index.js, structured exceptions (BridgeError, CircuitNotFoundError, ProofVerificationError), and a `bolyra[langchain]` extras install that includes the BolyraAuthTool BaseTool wrapper.

## Status

Placeholder — awaiting implementation.
