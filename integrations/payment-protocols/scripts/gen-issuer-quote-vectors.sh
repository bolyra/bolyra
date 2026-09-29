#!/usr/bin/env bash
# Generate independently signed full-profile issuer-quote fixtures with
# OpenSSL (not jose): ES256 and ES384, Tavily agent-pay claim shape, fixed
# times. Python is used only for base64url and DER (r,s) unpacking, never
# for any cryptographic operation. Output: test/fixtures/x402-issuer-quote/openssl-<alg>.json
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=test/fixtures/x402-issuer-quote
NOW=1790697736
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

gen() {
  local alg=$1 curve=$2 hash=$3 coord=$4 kid=$5
  openssl ecparam -genkey -name "$curve" -noout -out "$TMP/key.pem" 2>/dev/null
  openssl ec -in "$TMP/key.pem" -pubout -outform DER -out "$TMP/pub.der" 2>/dev/null
  local header payload
  header=$(printf '{"alg":"%s","kid":"%s","typ":"JWT"}' "$alg" "$kid")
  payload=$(printf '{"iss":"https://x402.tavily.com","aud":"aws:marketplace","iat":%d,"exp":%d,"jti":"openssl-%s-fixture","price":{"amount":"0.016","currency":"USD"},"payTo":"seller","reference":"tavily-search-advanced","settlement":{"product_id":"prod-maeet6sajeg42"}}' "$NOW" "$((NOW+300))" "$alg")
  local h p
  h=$(printf '%s' "$header" | python3 -c 'import sys,base64;print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).rstrip(b"=").decode())')
  p=$(printf '%s' "$payload" | python3 -c 'import sys,base64;print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).rstrip(b"=").decode())')
  printf '%s.%s' "$h" "$p" > "$TMP/input.txt"
  openssl dgst "-$hash" -sign "$TMP/key.pem" -out "$TMP/sig.der" "$TMP/input.txt"
  python3 - "$alg" "$curve" "$coord" "$kid" "$TMP" "$OUT" "$NOW" <<'PY'
import sys, json, base64, subprocess
alg, curve, coord, kid, tmp, out, now = sys.argv[1:8]
coord = int(coord)
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
spki = open(f'{tmp}/pub.der','rb').read()
point = spki[-(1+2*coord):]
assert point[0] == 4, 'expected an uncompressed EC point'
x, y = point[1:1+coord], point[1+coord:]
der = open(f'{tmp}/sig.der','rb').read()
# DER SEQUENCE { INTEGER r, INTEGER s }
assert der[0] == 0x30
i = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7f)
def read_int(i):
    assert der[i] == 0x02; n = der[i+1]; v = der[i+2:i+2+n]; return v.lstrip(b'\x00'), i+2+n
r, i = read_int(i); s, i = read_int(i)
raw = r.rjust(coord, b'\x00') + s.rjust(coord, b'\x00')
signing_input = open(f'{tmp}/input.txt','rb').read().decode()
compact = f'{signing_input}.{b64u(raw)}'
crv = {'prime256v1':'P-256','secp384r1':'P-384'}[curve]
fixture = {
  '_source': f'signed with {subprocess.run(["openssl","version"],capture_output=True,text=True).stdout.strip()} (not jose); header/payload hand-built; DER->raw r||s unpacked in python without any crypto',
  'alg': alg, 'kid': kid,
  'publicJwk': {'kty':'EC','crv':crv,'x':b64u(x),'y':b64u(y)},
  'compact': compact,
  'claims': json.loads(base64.urlsafe_b64decode(signing_input.split('.')[1]+'==')),
  'now': int(now),
}
json.dump(fixture, open(f'{out}/openssl-{alg}.json','w'), indent=1)
print('wrote', f'{out}/openssl-{alg}.json', 'sig bytes', len(raw))
PY
}

gen ES256 prime256v1 sha256 32 openssl-es256-key
gen ES384 secp384r1 sha384 48 openssl-es384-key
