# T12_screening_classifier — Screening classifier (benchmarks/oracles/adjudicate.py::classify)

The classifier the corpus-level use/mention result rests on, run on real corpus lines. Rows 8-10 are the ones an earlier version got wrong: it stripped non-alphanumerics before searching, so `3DES` matched inside `CODES`, `DESC` and `SITE_DESCRIPTION`, and 240 non-cryptographic lines on one repository were scored as real code. Measured agreement with hand labels is in `benchmarks/adjudication/`.

| case | line | family | classification |
|---|---|---|---|
| real call | `mac := hmac.New(sha256.New, key)` | SHA | code |
| real call, digit boundary | `hashlib.md5(b'x')` | MD5 | code |
| constructor | `des.NewTripleDESCipher(key)` | 3DES | code |
| quoted argument | `Cipher.getInstance("DESede/CBC/PKCS5Padding"` | 3DES | string-literal |
| string literal only | `banned = ['RC4', 'MD5']` | RC4 | string-literal |
| whole-line comment | `// ARC4 is a stream cipher` | RC4 | comment |
| trailing comment | `x = 1  # uses MD5 historically` | MD5 | comment |
| substring in identifier | `id: CODES.BadResponse,` | 3DES | substring |
| substring, SQL | `ORDER BY created_at DESC` | 3DES | substring |
| substring, camelCase | `const SITE_DESCRIPTION = 'hi'` | 3DES | substring |
| name absent entirely | `int main(void) { return 0; }` | RSA | substring |
| category it will not judge | `password = "hunter2"` | HARDCODED PASSWORD/SECRET | not-applicable |
| empty line | `(empty)` | MD5 | not-applicable |
| empty algorithm | `hashlib.md5(b'x')` | (empty) | not-applicable |
