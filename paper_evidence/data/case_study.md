# Case study: one finding, both arms, end to end

The migration pipeline's validation gate, run for real over the 26-repository corpus
(`phase3_migration.py`), and one finding both arms accepted, re-run once here so the
actual patch text can be quoted -- the corpus run validates `PatchProposal` objects in
memory and never writes them to disk, so this is the same call, repeated and captured.

## Aggregate result, 26 repositories, both arms (`data/migration_outcomes.csv`)

| arm | n | accepted | no codemod | error | failed validation |
|---|---|---|---|---|---|
| llm | 34 | 10 (29.4%) | 0 | 22 | 2 |
| template | 34 | 9 (26.5%) | 14 | 7 | 4 |

`accepted` means the patch passed every stage the validator ran (`applies`, `parses`,
and `rescan` always; `compiles`/`tests` when a toolchain for that language was
available). It does not mean *fully verified* -- most stages ran without a Docker
toolchain configured for that language, so `compiles`/`tests` show as `skipped` rather
than `pass`, which is scored honestly as `partial`. Where a toolchain WAS available
(PHP via `laravel-debugbar`, Go/C via `mpv-player/mpv` and `openwrt/openwrt`),
compilation genuinely ran and genuinely failed on two mpv/openwrt cases -- both arms,
not just the LLM's -- which is the validator doing its job rather than a defect.

`no-codemod` is not a template-arm failure: it is the arm correctly declining to
attempt a rule that has no deterministic transform, which is most of the pipeline's
LLM-only rule set (signatures, key exchange, MACs). `error` on the LLM arm is
dominated (15 of 22) by the model's own rewrite being rejected by the verifier after
3 attempts -- the safety gate refusing a bad patch, not silently shipping one.

## The same finding, both arms

`multica-ai/multica`, `code-weakhash-02` (SHA-1 -> a PQC-appropriate hash), `server/internal/auth/cloudfront.go:149`.

### LLM arm

generator: `llm`, model: `qwen2.5-coder:7b-instruct-q4_K_M`, status: `proposed`

```diff
--- a/server/internal/auth/cloudfront.go
+++ b/server/internal/auth/cloudfront.go
@@ -5,8 +5,7 @@
 	"crypto"
 	"crypto/rand"
 	"crypto/rsa"
-	"crypto/sha1"
-	"crypto/x509"
+	"crypto/sha256"
 	"encoding/base64"
 	"encoding/pem"
 	"fmt"
@@ -144,9 +143,9 @@
 
 	encodedPolicy := cfBase64Encode([]byte(policy))
 
-	h := sha1.New()
+	h := sha256.New()
 	h.Write([]byte(policy))
-	sig, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA1, h.Sum(nil))
+	sig, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, h.Sum(nil))
 	if err != nil {
 		slog.Error("failed to sign CloudFront policy", "error", err)
 		return nil
@@ -180,9 +179,9 @@
 
 	encodedPolicy := cfBase64Encode([]byte(policy))
 
-	h := sha1.New()
+	h := sha256.New()
 	h.Write([]byte(policy))
-	sig, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA1, h.Sum(nil))
+	sig, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, h.Sum(nil))
 	if err != nil {
 		slog.Error("failed to sign CloudFront URL", "error", err)
 		return rawURL
```

Validation: {"applies": {"status": "pass", "detail": "", "duration_s": 0.015}, "parses": {"status": "pass", "detail": "parses with no errors", "duration_s": 0.0}, "compiles": {"status": "skipped", "detail": "no single-file compile check for go \u2014 it needs a project to build", "duration_s": 0.0}, "tests": {"status": "skipped", "detail": "test sandbox is python-only (got go)", "duration_s": 0.0}, "rescan": {"status": "pass", "detail": "rescan ok. algorithms: {'SHA-256', 'RSA'}", "duration_s": 3.407}}

### Template arm

generator: `template`, status: `proposed`

```diff
--- a/server/internal/auth/cloudfront.go
+++ b/server/internal/auth/cloudfront.go
@@ -5,7 +5,7 @@
 	"crypto"
 	"crypto/rand"
 	"crypto/rsa"
-	"crypto/sha1"
+	"crypto/sha256"
 	"crypto/x509"
 	"encoding/base64"
 	"encoding/pem"
@@ -144,9 +144,9 @@
 
 	encodedPolicy := cfBase64Encode([]byte(policy))
 
-	h := sha1.New()
+	h := sha256.New()
 	h.Write([]byte(policy))
-	sig, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA1, h.Sum(nil))
+	sig, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, h.Sum(nil))
 	if err != nil {
 		slog.Error("failed to sign CloudFront policy", "error", err)
 		return nil
@@ -180,9 +180,9 @@
 
 	encodedPolicy := cfBase64Encode([]byte(policy))
 
-	h := sha1.New()
+	h := sha256.New()
 	h.Write([]byte(policy))
-	sig, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA1, h.Sum(nil))
+	sig, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, h.Sum(nil))
 	if err != nil {
 		slog.Error("failed to sign CloudFront URL", "error", err)
 		return rawURL
```

Validation: {"applies": {"status": "pass", "detail": "", "duration_s": 0.015}, "parses": {"status": "pass", "detail": "parses with no errors", "duration_s": 0.0}, "compiles": {"status": "skipped", "detail": "no single-file compile check for go \u2014 it needs a project to build", "duration_s": 0.0}, "tests": {"status": "skipped", "detail": "test sandbox is python-only (got go)", "duration_s": 0.0}, "rescan": {"status": "pass", "detail": "rescan ok. algorithms: {'SHA-256', 'RSA'}", "duration_s": 3.219}}

## A real capability boundary, not a defect

`redis/redis`, `deps/hiredis/test.sh` calls `openssl genrsa 2048` / `4096`, correctly
detected as `RSA-2048`/`RSA-4096` key generation. `code-kex-01` deliberately excludes
`.sh` from its file-suffix match -- `openssl genrsa` / `ssh-keygen -t rsa` have no
ML-KEM equivalent to rewrite into, and shell key exchange is documented in the rule
file itself as manual work, not an LLM target. `generate_patch` raises `No rule
matches asset`, the task is marked failed with resolution left for a human, and the
pipeline does not attempt a rewrite it cannot express. Reported here as the intended
behaviour it is.
