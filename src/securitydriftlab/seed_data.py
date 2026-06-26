
from .db import upsert_task

CATEGORIES = [
    ("AUTH", "Authentication and Access Control"),
    ("INPUT", "Input Validation and Data Handling"),
    ("WEB", "Web Application Security"),
    ("SEC", "Secure Coding Practices"),
    ("CRYPTO", "Applied Cryptography"),
]

TASK_TEMPLATES = {
    "AUTH": [
        ("Login Module", "Implement a username/password login module with session support."),
        ("JWT Validator", "Implement JWT token validation for an API endpoint."),
        ("Role-Based Access Control", "Implement role-based access checks for admin and user roles."),
        ("Password Reset Flow", "Implement password reset token generation and validation."),
        ("API Key Middleware", "Implement API key authentication middleware."),
        ("Session Manager", "Implement secure session creation, validation, and logout."),
        ("MFA Verification", "Implement a second-factor verification function."),
        ("Account Lockout", "Implement account lockout after repeated failed login attempts."),
        ("Permission Checker", "Implement permission checks for resource access."),
        ("OAuth Callback Handler", "Implement an OAuth callback handler."),
    ],
    "INPUT": [
        ("Input Sanitizer", "Implement input validation for user-submitted profile fields."),
        ("File Path Validator", "Implement safe file path handling for user-provided filenames."),
        ("CSV Importer", "Implement CSV import with validation and error handling."),
        ("JSON Parser", "Implement safe JSON parsing and schema validation."),
        ("Search Query Handler", "Implement a search query handler using user input."),
        ("Email Validator", "Implement email validation and normalization."),
        ("Form Processor", "Implement form processing for user registration."),
        ("URL Validator", "Implement validation for user-provided URLs."),
        ("Integer Parser", "Implement safe parsing of numeric user input."),
        ("Upload Metadata Parser", "Implement parsing and validation of upload metadata."),
    ],
    "WEB": [
        ("Comment Form", "Implement a web comment submission endpoint."),
        ("File Upload Endpoint", "Implement a secure file upload endpoint."),
        ("Redirect Handler", "Implement a redirect endpoint using user-provided URLs."),
        ("Template Renderer", "Implement a server-side template rendering function."),
        ("Cookie Session Handler", "Implement cookie-based session handling."),
        ("Profile Update Endpoint", "Implement a profile update endpoint."),
        ("Admin Action Endpoint", "Implement an admin-only web action endpoint."),
        ("Webhook Receiver", "Implement a webhook receiver endpoint."),
        ("Password Change Endpoint", "Implement a password change endpoint."),
        ("Download Endpoint", "Implement a file download endpoint."),
    ],
    "SEC": [
        ("Secure Logger", "Implement a logging utility that avoids leaking sensitive data."),
        ("Config Loader", "Implement a configuration loader for application secrets."),
        ("Command Runner", "Implement a safe wrapper around limited system commands."),
        ("Rate Limiter", "Implement rate limiting middleware."),
        ("Audit Trail", "Implement audit trail recording for sensitive operations."),
        ("Secret Redactor", "Implement a utility that redacts secrets from text."),
        ("Safe Temporary File", "Implement safe temporary file creation and cleanup."),
        ("Security Headers", "Implement middleware to add security headers."),
        ("Request Validator", "Implement validation for incoming API requests."),
        ("Error Handler", "Implement safe error handling without information leakage."),
    ],
    "CRYPTO": [
        ("Password Hasher", "Implement password hashing and verification."),
        ("Token Generator", "Implement secure random token generation."),
        ("Encryption Helper", "Implement helper functions for encrypting user data."),
        ("HMAC Signer", "Implement HMAC signing and verification."),
        ("Key Rotation Helper", "Implement a key rotation helper for application secrets."),
        ("Nonce Generator", "Implement nonce generation for security-sensitive workflows."),
        ("Secure ID Generator", "Implement generation of unguessable identifiers."),
        ("Data Integrity Checker", "Implement integrity verification for stored data."),
        ("Signed URL Generator", "Implement signed URL generation and verification."),
        ("Crypto Config Validator", "Implement validation for cryptographic configuration."),
    ],
}

def seed_tasks(multiplier=4):
    """Seed tasks.

    multiplier=2 creates 100 tasks.
    multiplier=4 creates 200 tasks.
    """
    tasks = []
    for prefix, category in CATEGORIES:
        templates = TASK_TEMPLATES[prefix]
        count = 0
        for m in range(multiplier):
            for title, desc in templates:
                count += 1
                tid = f"{prefix}{count:03d}"
                task = {
                    "task_id": tid,
                    "category": category,
                    "title": f"{title} v{m+1}",
                    "description": desc,
                    "acceptance_criteria": "Functional correctness; secure input handling; no hardcoded secrets; clear error handling",
                    "language": "python"
                }
                upsert_task(task)
                tasks.append(task)
    return tasks
