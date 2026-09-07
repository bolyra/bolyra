I'll read the pinned draft text at the base commit so the diff hunks match the actual pseudocode.


<invoke name="Bash">
<parameter name="command">git -C .. show a4f546f3279706a2b28a0c15569c0040425e84c7:spec/draft-kondoju-evc-01.md | grep -n -e 'pseudo' -e 'non-zero exit' -e 'timed_out' -e 'consume_nonces or' -e 'No other code path' -e '^#' | head -80</parameter>
</invoke>
<parameter name="description">Locate pseudocode and target sentences in pinned draft</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">git -C .. show a4f546f3279706a2b28a0c15569c0040425e84c7:spec/external-verifier-contract-v1.md | grep -n -e 'No other code path' -e 'schema_invalid' -e 'signal_death' -e 'output_bound' -e 'nonzero_exit' -e '^### 16' -e '^## 1[0-9]' </parameter>
<parameter name="description">Locate §5.1 sentence and §16.3 classification tokens in pinned contract</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">git -C .. show a4f546f3279706a2b28a0c15569c0040425e84c7:spec/draft-kondoju-evc-01.md | grep -n -c '' ; git -C .. show a4f546f3279706a2b28a0c15569c0040425e84c7:spec/draft-kondoju-evc-01.md | grep -n -A45 -B25 'consume_nonces or'</parameter>
<parameter name="description">Extract full pseudocode block from pinned draft</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">git -C .. show a4f546f3279706a2b28a0c15569c0040425e84c7:spec/external-verifier-contract-v1.md | sed -n '/^### 16.3/,/^### 16.4\|^## 17/p' | head -80; echo ----; git -C .. show a4f546f3279706a2b28a0c15569c0040425e84c7:spec/draft-kondoju-evc-01.md | grep -n -B3 -A12 'No other code path'</parameter>
<parameter name="description">Read §16.3 classification tokens and draft fd-isolation sentence</parameter>
</invoke>
<invoke name="Bash">
<parameter name="command">ls ../spec/fixtures/host-conformance/ | head -40; ls ../spec/fixtures/host-conformance/ | wc -l</parameter>
<parameter name="description">List host-conformance vectors to reference relevant IDs</parameter>
</invoke>
