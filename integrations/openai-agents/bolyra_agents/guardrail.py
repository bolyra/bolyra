"""BolyraAuthGuardrail -- InputGuardrail for Bolyra credential verification.

Coarse-grained auth check: "is this agent allowed to run at all?"
Runs before (or in parallel with) the agent's LLM call.

On failure, sets ``tripwire_triggered=True`` which causes the OpenAI Agents
SDK to raise ``InputGuardrailTripwireTriggered`` and halt the agent run.

On success, stores the AuthResult in the run context under ``bolyra_auth``
so downstream tools can access verification state without re-verifying.
"""

from __future__ import annotations

import os
import warnings
from typing import Any

from agents import Agent, InputGuardrail, GuardrailFunctionOutput
from agents.run_context import RunContextWrapper

from bolyra_agents._tracing import bolyra_auth_span, record_auth_result
from bolyra_agents._verify import verify_credentials
from bolyra_agents.auth_context import BolyraAuthContext
from bolyra_agents.types import AuthResult, BolyraAuthError


class BolyraAuthGuardrail:
    """InputGuardrail that verifies Bolyra credentials before agent execution.

    Usage::

        from bolyra_agents import BolyraAuthGuardrail, BolyraAuthContext, AuthMode

        ctx = BolyraAuthContext(
            mode=AuthMode.SD_JWT,
            receipt=receipt,
            holder_private_key=agent_key,
            issuer_public_key=operator_pub,
        )
        guardrail = BolyraAuthGuardrail(auth_context=ctx)
        agent = Agent(
            name="my-agent",
            instructions="You are a helpful assistant.",
            input_guardrails=[guardrail.as_input_guardrail()],
        )

    The guardrail stores the verification result in ``ctx.context["bolyra_auth"]``
    so downstream tool wrappers can skip re-verification.
    """

    def __init__(
        self,
        auth_context: BolyraAuthContext,
        name: str = "bolyra_auth",
        run_in_parallel: bool = True,
    ):
        self.auth_context = auth_context
        self._name = name
        self._run_in_parallel = run_in_parallel

    def as_input_guardrail(self) -> InputGuardrail:
        """Create an InputGuardrail instance for use with the Agent constructor.

        Returns:
            An InputGuardrail that wraps this guardrail's check function.
        """
        return InputGuardrail(
            guardrail_function=self._check_auth,
            name=self._name,
            run_in_parallel=self._run_in_parallel,
        )

    async def _check_auth(
        self,
        ctx: RunContextWrapper,
        agent: Agent,
        input: str | list,
    ) -> GuardrailFunctionOutput:
        """Verify credentials and return guardrail output.

        Args:
            ctx: The run context wrapper.
            agent: The agent being guarded.
            input: The agent input (string or message list).

        Returns:
            GuardrailFunctionOutput with tripwire_triggered on auth failure.
        """
        with bolyra_auth_span(
            "guardrail",
            agent_id=self.auth_context.agent_id,
            agent_name=getattr(agent, "name", "unknown"),
        ) as span:
            # Dev mode bypass
            if self.auth_context.dev_mode:
                if os.environ.get("BOLYRA_ENV") == "production":
                    raise BolyraAuthError("dev_mode=True is not allowed when BOLYRA_ENV=production")
                warnings.warn("Bolyra: dev_mode is active. Do not use in production.", stacklevel=2)
                record_auth_result(span, ok=True, reason="dev_mode")
                dev_result = AuthResult(
                    ok=True,
                    claims={"dev_mode": True},
                    permissions=self.auth_context.required_permissions,
                    agent_id=self.auth_context.agent_id,
                )
                # Store in context if context is a dict
                if hasattr(ctx, "context") and isinstance(ctx.context, dict):
                    ctx.context["bolyra_auth"] = dev_result
                return GuardrailFunctionOutput(
                    output_info={"status": "pass", "mode": "dev"},
                    tripwire_triggered=False,
                )

            # Validate config
            errors = self.auth_context.validate()
            if errors:
                record_auth_result(span, ok=False, reason="config_invalid")
                return GuardrailFunctionOutput(
                    output_info={"status": "fail", "errors": errors},
                    tripwire_triggered=True,
                )

            # Verify credentials
            result = await verify_credentials(self.auth_context)

            record_auth_result(span, ok=result.ok, reason=result.reason)

            if not result.ok:
                return GuardrailFunctionOutput(
                    output_info={
                        "status": "fail",
                        "reason": result.reason,
                        "detail": result.detail,
                    },
                    tripwire_triggered=True,
                )

            # Store verification result in run context for downstream use
            if hasattr(ctx, "context") and isinstance(ctx.context, dict):
                ctx.context["bolyra_auth"] = result

            return GuardrailFunctionOutput(
                output_info={
                    "status": "pass",
                    "agent_id": result.agent_id,
                    "permissions": result.permissions,
                },
                tripwire_triggered=False,
            )
