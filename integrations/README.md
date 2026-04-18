# Bolyra Framework Integrations

Python-based integrations that let AI agents use Bolyra for mutual authentication and scoped delegation.

## Integrations

| Framework | Directory | Tools |
|-----------|-----------|-------|
| [LangChain](langchain/) | `integrations/langchain/` | `BolyraAuthTool`, `BolyraDelegateTool` |
| [CrewAI](crewai/) | `integrations/crewai/` | `BolyraAuthTool`, `BolyraDelegateTool` |

## What these do

- **BolyraAuthTool** -- Mutual ZKP authentication. Agent proves credential validity (PLONK), counterparty proves group membership (Groth16). Neither learns private information beyond policy satisfaction.
- **BolyraDelegateTool** -- Scoped permission delegation with cryptographic narrowing. Delegatee cannot exceed granted permissions.

## Status

API shape and tool contracts are final. Currently stubs pending `@bolyra/sdk` v0.2 circuit wiring.

## Install

```bash
pip install -r integrations/requirements.txt
npm install @bolyra/sdk && npx bolyra setup
```
