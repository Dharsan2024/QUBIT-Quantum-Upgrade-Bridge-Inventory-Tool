"""Per-class vocabularies for the sensitivity-classifier training-data synthesizer (doc 02 §6.3.4).

Each of the 7 sensitivity classes (``unknown`` is the abstention outcome, never predicted) gets
identifier stems, comment fragments, and file-path fragments. These are deliberately broader than
the heuristic ``sensitivity_rules.yaml`` regexes so a trained model can generalize past the rules
(the whole point of Tier 2). Distractor tokens are class-neutral noise mixed into every example.
"""

from __future__ import annotations

# The 7 predicted classes (order fixed for stable label ids).
CLASSES: list[str] = ["phi", "financial", "pii", "credentials", "ip", "ephemeral", "public"]

IDENTIFIERS: dict[str, list[str]] = {
    "phi": [
        "patient_id", "patient_record", "diagnosis", "diagnostic_code", "icd10_code", "hl7_message",
        "fhir_resource", "medical_record", "mrn", "prescription", "ehr_entry", "lab_result",
        "blood_type", "treatment_plan", "clinical_note", "immunization", "allergy_list",
    ],
    "financial": [
        "card_number", "card_num", "pan", "cvv", "iban", "swift_code", "account_balance",
        "txn_id", "payment_intent", "invoice_total", "payroll_run", "billing_address",
        "routing_number", "ledger_entry", "settlement", "wire_transfer", "credit_limit",
    ],
    "pii": [
        "ssn", "social_security", "aadhaar", "passport_no", "national_id", "date_of_birth", "dob",
        "driver_license", "email_address", "phone_number", "home_address", "first_name",
        "last_name", "customer_profile", "tax_id", "voter_id",
    ],
    "credentials": [
        "password", "passwd", "secret_key", "api_key", "bearer_token", "jwt_secret",
        "refresh_token", "private_key", "client_secret", "auth_token", "session_secret",
        "master_key", "signing_key", "vault_token", "db_password",
    ],
    "ip": [
        "proprietary_algo", "trade_secret", "confidential_spec", "internal_only", "patent_draft",
        "source_blueprint", "design_doc", "roadmap_internal", "pricing_model", "secret_recipe",
        "unreleased_feature", "acquisition_memo",
    ],
    "ephemeral": [
        "session_id", "session_token", "nonce", "csrf_token", "cache_key", "otp_code",
        "temp_token", "request_id", "correlation_id", "one_time_code", "captcha_value",
        "throwaway_key",
    ],
    "public": [
        "sitemap_entry", "robots_txt", "healthz_status", "public_asset", "static_banner",
        "press_release", "changelog_note", "faq_item", "open_dataset", "cdn_url",
        "marketing_copy", "public_docs",
    ],
}

COMMENTS: dict[str, list[str]] = {
    "phi": [
        "store patient diagnosis for the EHR",
        "HL7 feed of protected health information",
        "retain medical record per HIPAA",
        "hash the patient MRN before export",
    ],
    "financial": [
        "store PAN for recurring billing",
        "encrypt cardholder data (PCI-DSS)",
        "settle the wire transfer ledger",
        "protect payment account balance",
    ],
    "pii": [
        "personally identifiable info, GDPR scope",
        "hash the SSN before persisting",
        "customer date of birth and address",
        "national id lookup",
    ],
    "credentials": [
        "never log the plaintext password",
        "rotate the API signing key",
        "store the bearer refresh token securely",
        "hash credentials with a strong KDF",
    ],
    "ip": [
        "confidential — proprietary pricing model",
        "trade secret, internal only",
        "unreleased patent draft",
        "do not disclose: acquisition memo",
    ],
    "ephemeral": [
        "short-lived session nonce",
        "one-time OTP, expires in 60s",
        "throwaway cache key",
        "CSRF token per request",
    ],
    "public": [
        "public marketing asset, no secrets",
        "served from the CDN, world-readable",
        "healthz endpoint status",
        "open dataset, freely distributable",
    ],
}

FILE_PATHS: dict[str, list[str]] = {
    "phi": ["src/ehr/records.py", "app/clinical/patient.py", "services/hl7/ingest.py"],
    "financial": ["src/billing/payments.py", "app/ledger/settle.py", "services/payroll/run.py"],
    "pii": ["src/identity/profile.py", "app/kyc/verify.py", "services/users/pii.py"],
    "credentials": ["src/auth/login.py", "app/security/tokens.py", "services/vault/keys.py"],
    "ip": ["src/internal/pricing.py", "app/rnd/blueprint.py", "docs/confidential/roadmap.py"],
    "ephemeral": ["src/session/store.py", "app/cache/keys.py", "services/otp/issue.py"],
    "public": ["public/sitemap.py", "static/assets.py", "www/marketing.py"],
}

# Class-neutral distractor identifiers/comments mixed into every example so the model can't
# key off "any domain word present" — it must weigh the dominant signal.
DISTRACTOR_IDS: list[str] = [
    "index", "counter", "buffer", "result", "handler", "config", "timeout", "retry_count",
    "logger", "response", "payload", "offset", "batch_size", "iterator", "temp_dir", "status_code",
]
DISTRACTOR_COMMENTS: list[str] = [
    "refactor later",
    "TODO: add tests",
    "performance-sensitive path",
    "keep the interface stable",
    "handle the edge case",
]

# Crypto call snippets per language — the finding the scanner would flag. {ids} is substituted
# with a comma-joined identifier list drawn from the target class + distractors.
CODE_TEMPLATES: dict[str, list[str]] = {
    "python": [
        "import hashlib\n{comment}\n{a} = hashlib.sha1({b}.encode()).hexdigest()",
        "from cryptography.hazmat.primitives.asymmetric import rsa\n{comment}\nkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # {a}",
        "import hashlib\n{comment}\ndigest = hashlib.md5({a}).digest()  # {b}",
        "import jwt\n{comment}\ntoken = jwt.encode({{'sub': {a}}}, secret, algorithm='HS256')",
    ],
    "java": [
        "// {comment}\nMessageDigest md = MessageDigest.getInstance(\"SHA-1\"); // {a}\nbyte[] h = md.digest({b}.getBytes());",
        "// {comment}\nKeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\"); kpg.initialize(2048); // {a}",
        "// {comment}\nCipher c = Cipher.getInstance(\"RSA/ECB/PKCS1Padding\"); // {a} {b}",
    ],
    "go": [
        "// {comment}\nh := md5.Sum([]byte({a})) // {b}",
        "// {comment}\nkey, _ := rsa.GenerateKey(rand.Reader, 2048) // {a}",
        "// {comment}\nsum := sha1.Sum([]byte({a})) // {b}",
    ],
    "javascript": [
        "// {comment}\nconst hash = crypto.createHash('sha1').update({a}).digest('hex');",
        "// {comment}\nconst token = jwt.sign({{ sub: {a} }}, secret); // {b}",
    ],
}

LANGUAGES: list[str] = list(CODE_TEMPLATES.keys())
