"""Brace-safe, single-pass template rendering.

str.format() cannot be used on the prompt templates: they contain literal
JSON examples whose braces format() interprets as placeholders (found live
in iteration 1: KeyError '"id"'). render() substitutes ONLY the named keys,
in ONE pass over the original template — substituted values are never
re-scanned, so untrusted candidate/artifact text containing '{checks}' or
similar cannot be rewritten (Codex review finding).
"""
from __future__ import annotations

import re


def render(template: str, **kw: object) -> str:
    if not kw:
        return template
    pattern = re.compile("|".join(r"\{" + re.escape(k) + r"\}" for k in kw))
    return pattern.sub(lambda m: str(kw[m.group(0)[1:-1]]), template)
