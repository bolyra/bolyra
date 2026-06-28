# Audit: SD-JWT Module + LangChain Adapter (2026-06-19)

## Scope
- `sdk-python/bolyra/sd_jwt.py`
- `integrations/langchain/bolyra_langchain/` (auth_tool, delegate_tool, sd_jwt_tool, session, types, callbacks)

## Findings Summary
| ID | Severity | Component | One-liner |
|----|----------|-----------|-----------|
| C1 | CRITICAL | sd_jwt_tool.py:143 | Full bearer credential (presented SD-JWT) returned in LLM context |
| C2 | CRITICAL | sd_jwt_tool.py:89-141 | Tool holds both issuer and holder keys, self-signs and self-presents |
| H1 | HIGH | all 3 tools | No dev mode guard; silent fallback to dev credentials |
| H2 | HIGH | session.py:148 | No 3-hop delegation limit enforced |
| H3 | HIGH | all 3 tools | Exception str(e) may leak key material to LLM context |
| H4 | HIGH | sd_jwt.py:489-500 | Timing side-channel: != for nonce/sd_hash/audience |
| M1 | MEDIUM | sd_jwt.py:38 | Unused decode_dss_signature import |
| M2 | MEDIUM | sd_jwt.py verify() | max_amount claim not validated |
| M3 | MEDIUM | session.py:153 | scope_commitment overridable via tool input schema |
| L1 | LOW | all 3 tools _arun | Deprecated get_event_loop() |
| L2 | LOW | callbacks.py | Bolyra-specific hooks never called by tools |
| L3 | LOW | auth_tool.py:34 | required_permissions not validated at input parse time |

## Regression Check
- 990c4df (spend cap): M2 gap -- verify() doesn't enforce max claim
- 51b4b81 (scopeCommitment): M3 gap -- tool input allows override
- 565c5cc (3 hops): H2 gap -- Session doesn't enforce
- Other 6 fixes: no regression found
