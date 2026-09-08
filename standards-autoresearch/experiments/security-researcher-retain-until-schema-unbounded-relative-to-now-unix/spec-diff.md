I'll fetch the pinned file, locate the four edit sites, and build a real unified diff with exact hunk ranges.


Bash
{
  "command": "git show 9bf754441ab36ab93992ed5936d34c44a4128f92:spec/external-verifier-contract-v1.md > /tmp/evc-pinned.md && wc -l /tmp/evc-pinned.md && grep -n 'retain_until\\|^### 3.5\\|^### 7.2\\|^### 7.3\\|Record after proceeding\\|disallowed additional property\\|If \\*\\*any\\*\\* insert' /tmp/evc-pinned.md"
}
