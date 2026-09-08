I'll extract the pinned file at the base commit, apply the artifact's edits to a copy, and regenerate the diff with `git diff` so every hunk header is computed rather than hand-written.


<invoke name="Bash">
<parameter name="command">mkdir -p /tmp/sar-diff && git show 9bf754441ab36ab93992ed5936d34c44a4128f92:spec/external-verifier-contract-v1.md > /tmp/sar-diff/base.md && cp /tmp/sar-diff/base.md /tmp/sar-diff/new.md && wc -l /tmp/sar-diff/base.md && grep -n "### 3.2 Allow with host-owned\|consume_nonces\` (array of objects\|kind\` is \*\*advisory\|### 7.3 Reserve-before-act\|Record after proceeding\|\*\*local (default)" /tmp/sar-diff/base.md</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cd /tmp/sar-diff && sed -n '140,165p;165,185p' base.md</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cd /tmp/sar-diff && sed -n '295,315p' base.md; echo ----; sed -n '470,520p' base.md</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cd /tmp/sar-diff && git ls-tree -r 9bf754441ab36ab93992ed5936d34c44a4128f92 --name-only | grep -c . </parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">sleep 0</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cd /tmp/sar-diff && cat > apply.py <<'PY'
import re,sys
s=open('new.md').read()
def rep(old,new):
    global s
    assert s.count(old)==1, ("NOT UNIQUE/FOUND", old[:80], s.count(old))
    s=s.replace(old,new)

rep("""Emitted only in host nonce mode (§8). Instructs the host to durably record each
one-time nonce so the same proof cannot be replayed. A presentation can carry
more than one nonce to reserve — e.g. the agent nullifier **plus** a
""","""A conforming verifier emits this shape only in host nonce mode (§8). It
instructs the host to durably record each one-time nonce so the same proof
cannot be replayed. The host's reservation obligation (§7.3) attaches to the
**presence** of `consume_nonces` on the verdict, not to the nonce mode the host
believes it configured: a host that receives this shape while configured for
local mode **MUST** still reserve every entry. A presentation can carry
more than one nonce to reserve — e.g. the agent nullifier **plus** a
""")

rep("""  burn). The host **MUST** reserve-before-act **EACH** entry (§7.3). Each entry:
""","""  burn). The host **MUST** reserve-before-act **EACH** entry (§7.3), regardless
  of its configured nonce mode. Each entry:
""")

rep("""  The `verdict`, `code`, and (in host nonce mode) `consume_nonces` fields are the
""","""  The `verdict`, `code`, and (when present) `consume_nonces` fields are the
""")

rep("""### 7.3 Reserve-before-act (host nonce mode)

When the host runs the verifier in **host nonce mode** (§8) and receives
`allow` with `consume_nonces`, the host **MUST** reserve **every** entry in the
list **before** performing the privileged action:
""","""### 7.3 Reserve-before-act (whenever `consume_nonces` is present)

When the host receives `allow` with `consume_nonces`, the host **MUST** reserve
**every** entry in the list **before** performing the privileged action. This
obligation is **mode-independent**: it is triggered by the presence of
`consume_nonces` on the verdict, not by the nonce mode the host configured
(§8). A conforming verifier emits `consume_nonces` only in host nonce mode, but
nonce mode is an out-of-band configuration agreement with no in-band signal, so
a host **MUST NOT** infer from its own configuration that the list may be
ignored. A host configured for local mode that receives `consume_nonces`
**MUST** reserve every entry exactly as a host-mode host would. A host that
cannot reserve — it has no durable nonce store, or the store errors — **MUST**
deny the action; it **MUST NOT** proceed on the strength of the verifier's
`allow` alone.

The reservation procedure:
""")

rep("""`allow` in host mode is **conditional** on every host insert being novel.
""","""`allow` is **conditional** on every host insert being novel whenever
`consume_nonces` is present.
""")

rep("""  errors, the verifier **MUST** fail closed (`deny code=internal_error`, non-zero
  exit).
- **host.**""","""  errors, the verifier **MUST** fail closed (`deny code=internal_error`, non-zero
  exit). A host configured for local mode **MUST NOT** assume it will never
  receive `consume_nonces`; if it does, §7.3 applies unchanged (reserve or
  deny).
- **host.**""")
open('new.md','w').write(s)
print("ok")
PY
python3 apply.py</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cd /tmp/sar-diff && git diff --no-index -U3 base.md new.md | sed 's#a/base.md#a/spec/external-verifier-contract-v1.md#; s#b/new.md#b/spec/external-verifier-contract-v1.md#' | sed '/^index /d; /^diff --git/d' > out.diff; cat out.diff; echo ====; cp base.md check.md && cd /tmp/sar-diff && patch --dry-run check.md out.diff && echo PATCH_OK</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cd /tmp/sar-diff && git diff --no-index base.md new.md > /dev/null; echo $?</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cd /tmp/sar-diff && awk '/^@@/{print}' out.diff</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cd /tmp/sar-diff && cat out.diff</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cd /tmp/sar-diff && ls; wc -l out.diff</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cd /tmp/sar-diff && ls -la && head -c 3000 out.diff</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cd /tmp/sar-diff && cat out.diff | head -200</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cd /tmp/sar-diff && wc -l base.md new.md && diff -u base.md new.md | head -5</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cd /tmp/sar-diff && python3 -c "print(open('out.diff').read())"</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cd /tmp/sar-diff && python3 -c "print(open('out.diff').read())" 2>&1 | cat</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cd /tmp/sar-diff && python3 apply.py; wc -l base.md new.md; diff -u base.md new.md > d2.diff; echo rc=$?; wc -l d2.diff; grep -n '^@@' d2.diff</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cd /tmp/sar-diff && cat d2.diff</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cd /tmp/sar-diff && cat d2.diff | od -c | head -3; stat -f '%z' d2.diff base.md new.md</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cd /tmp/sar-diff && ls -la /tmp/sar-diff/</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">ls -la /tmp/sar-diff/ 2>&1; echo "exit=$?"</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">echo hello; ls /tmp/sar-diff</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">echo hello</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">echo test123</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">git show 9bf754441ab36ab93992ed5936d34c44a4128f92:spec/external-verifier-contract-v1.md | wc -l</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">git show 9bf754441ab36ab93992ed5936d34c44a4128f92:spec/external-verifier-contract-v1.md | sed -n '146,180p'</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">git show 9bf754441ab36ab93992ed5936d34c44a4128f92:spec/external-verifier-contract-v1.md | grep -n "advisory metadata\|### 7.3\|Record after proceeding\|\*\*local (default)"</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">git show 9bf754441ab36ab93992ed5936d34c44a4128f92:spec/external-verifier-contract-v1.md | sed -n '298,308p;476,520p'</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">git show 9bf754441ab36ab93992ed5936d34c44a4128f92:spec/external-verifier-contract-v1.md > /tmp/evc-base.md; python3 - <<'PY'
s=open('/tmp/evc-base.md').read()
def rep(old,new):
    global s
    assert s.count(old)==1, ("NOT UNIQUE/FOUND", old[:80], s.count(old))
    s=s.replace(old,new)
rep("""Emitted only in host nonce mode (§8). Instructs the host to durably record each
one-time nonce so the same proof cannot be replayed. A presentation can carry
more than one nonce to reserve — e.g. the agent nullifier **plus** a
""","""A conforming verifier emits this shape only in host nonce mode (§8). It
instructs the host to durably record each one-time nonce so the same proof
cannot be replayed. The host's reservation obligation (§7.3) attaches to the
**presence** of `consume_nonces` on the verdict, not to the nonce mode the host
believes it configured: a host that receives this shape while configured for
local mode **MUST** still reserve every entry. A presentation can carry
more than one nonce to reserve — e.g. the agent nullifier **plus** a
""")
rep("""  burn). The host **MUST** reserve-before-act **EACH** entry (§7.3). Each entry:
""","""  burn). The host **MUST** reserve-before-act **EACH** entry (§7.3), regardless
  of its configured nonce mode. Each entry:
""")
rep("""  The `verdict`, `code`, and (in host nonce mode) `consume_nonces` fields are the
""","""  The `verdict`, `code`, and (when present) `consume_nonces` fields are the
""")
rep("""### 7.3 Reserve-before-act (host nonce mode)

When the host runs the verifier in **host nonce mode** (§8) and receives
`allow` with `consume_nonces`, the host **MUST** reserve **every** entry in the
list **before** performing the privileged action:
""","""### 7.3 Reserve-before-act (whenever `consume_nonces` is present)

When the host receives `allow` with `consume_nonces`, the host **MUST** reserve
**every** entry in the list **before** performing the privileged action. This
obligation is **mode-independent**: it is triggered by the presence of
`consume_nonces` on the verdict, not by the nonce mode the host configured
(§8). A conforming verifier emits `consume_nonces` only in host nonce mode, but
nonce mode is an out-of-band configuration agreement with no in-band signal, so
a host **MUST NOT** infer from its own configuration that the list may be
ignored. A host configured for local mode that receives `consume_nonces`
**MUST** reserve every entry exactly as a host-mode host would. A host that
cannot reserve — it has no durable nonce store, or the store errors — **MUST**
deny the action; it **MUST NOT** proceed on the strength of the verifier's
`allow` alone.

The reservation procedure:
""")
rep("""`allow` in host mode is **conditional** on every host insert being novel.
""","""`allow` is **conditional** on every host insert being novel whenever
`consume_nonces` is present.
""")
rep("""  errors, the verifier **MUST** fail closed (`deny code=internal_error`, non-zero
  exit).
- **host.**""","""  errors, the verifier **MUST** fail closed (`deny code=internal_error`, non-zero
  exit). A host configured for local mode **MUST NOT** assume it will never
  receive `consume_nonces`; if it does, §7.3 applies unchanged (reserve or
  deny).
- **host.**""")
open('/tmp/evc-new.md','w').write(s)
print("applied")
PY
diff -u /tmp/evc-base.md /tmp/evc-new.md | sed '1s#.*#--- a/spec/external-verifier-contract-v1.md#; 2s#.*#+++ b/spec/external-verifier-contract-v1.md#'</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">diff -u /tmp/evc-base.md /tmp/evc-new.md | sed '1s#.*#--- a/spec/external-verifier-contract-v1.md#; 2s#.*#+++ b/spec/external-verifier-contract-v1.md#' > /tmp/evc.diff; cp /tmp/evc-base.md /tmp/evc-check.md; cd /tmp && patch --dry-run -p1 -i /tmp/evc.diff evc-check.md; echo rc=$?; grep -n '^@@' /tmp/evc.diff</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cat /tmp/evc.diff</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">cat /tmp/evc.diff; echo "rc=$?"</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">wc -c /tmp/evc.diff /tmp/evc-base.md /tmp/evc-new.md 2>&1</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">echo start; cat /tmp/evc.diff; echo end</parameter>
</invoke>
