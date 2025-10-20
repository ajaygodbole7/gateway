
| Area | Summary                           | Decision                                                          | Rationale |
|------|-----------------------------------|-------------------------------------------------------------------|-----------|
| **Core Architecture** | Application-level encryption      | Encrypt at application layer, not database                        | Better key management control, cloud-agnostic, avoids DB vendor lock-in |
| **Core Architecture** | Entity design                     | JPA entities contain only ciphertext, never plaintext             | Prevents accidental exposure in heap dumps, serialization, or logs |
| **Core Architecture** | DTO pattern                       | Mutable request DTOs, immutable response records                  | Enables clearing sensitive data; prevents plaintext in responses |
| **Cryptography** | Encryption algorithm              | AES-256-GCM for authenticated encryption                          | FIPS-approved, provides confidentiality + integrity, hardware acceleration |
| **Cryptography** | Context binding                   | Column-specific AAD labels (e.g., "users.ssn")                    | Prevents moving ciphertext between columns, adds context binding |
| **Cryptography** | Key versioning                    | Embed version in ciphertext header `[verLen\|version\|IV\|ct]`    | Enables zero-downtime rotation, allows historical data decryption |
| **Cryptography** | Search mechanism                  | HMAC-SHA256 with pepper for equality search                       | Search without decryption, prevents rainbow tables, maintains performance |
| **Cryptography** | Display optimization              | Store last-4 digits separately                                    | Avoids decryption for UI display, improves performance |
| **Key Management** | Key storage                       | Azure Key Vault for all cryptographic keys                        | Hardware security, audit trails, automated rotation, compliance certs |
| **Key Management** | Historical keys                   | On-demand caching with bounded size (100 keys)                    | Balances security with performance, minimal memory residence |
| **Key Management** | Key scope                         | Single DEK for all users                                          | Simplifies management, acceptable for banking, avoids key proliferation |
| **Key Management** | Key separation                    | Separate HMAC pepper from DEK                                     | Enables independent rotation schedules, separation of concerns |
| **Data Flow** | Normalization                     | Strip formatting before hashing                                   | Consistent search regardless of input format |
| **Data Flow** | Field processing                  | Digits-only normalization for SSN/PAN/Account                     | Aligns with banking patterns, simplifies validation |
| **Data Flow** | URL security                      | Reject PII in query parameters and paths                          | Prevents exposure in logs, browser history, referrer headers |
| **Data Flow** | Search operations                 | POST body for PII searches, not GET                               | Keeps sensitive criteria out of URLs |
| **Security Controls** | Defense strategy                  | Multi-layer defense-in-depth                                      | No single point of failure, compensating controls |
| **Security Controls** | Authentication                    | OAuth2 JWT resource server with scopes                            | Stateless auth, standard protocol, delegated authorization |
| **Security Controls** | Step-up auth                      | Check JWT auth_time for modifications (15 min)                    | Prevents replay attacks, ensures user presence |
| **Security Controls** | Rate limiting                     | Different limits: read (100/min), write (10/min), search (10/min) | Prevents enumeration while allowing normal use |
| **Security Controls** | Response validation               | Guard filter blocks plaintext PII in responses                    | Catches developer mistakes, prevents accidental exposure |
| **Audit** | Log integrity                     | Append-only immutable audit table                                 | Database rules prevent tampering, meets regulatory requirements |
| **Audit** | Write pattern                     | Asynchronous audit logging                                        | Prevents impact on request latency |
| **Audit** | Context capture                   | Track request ID, purpose, duration, success/failure              | Enables forensics, supports compliance reporting |
| **Audit** | Purpose tracking for PCI/PII Data | Require X-Audit-Purpose header                                    | Documents why PII was accessed, regulatory requirement |
| **Performance** | Default behavior                  | Masked-only responses, no decryption                              | Reduces crypto operations, improves response times |
| **Performance** | Indexing strategy                 | Index only hash columns                                           | Maintains search performance without pattern exposure |
| **Performance** | Bulk operations                   | Avoid mass decryption                                             | Prevents performance degradation and key exposure |
| **Operations** | Key freshness                     | Refresh keys from vault hourly or at desired frequency            | Balances freshness with API limits |
| **Operations** | Log sanitization                  | Logback MessageConverter for PII redaction                        | Centralized sanitization for all appenders |
| **Operations** | Development mode                  | Local key generation option                                       | Enables local dev without Azure dependencies |
| **Operations** | Monitoring                        | Health endpoints with authorization                               | Enables monitoring without sensitive data exposure |
| **Database Design** | Table structure                   | Single table with encrypted, hash, and last4 columns              | Simplifies queries, maintains referential integrity |
| **Database Design** | Column types                      | TEXT for ciphertext (Base64 encoded)                              | Simplifies debugging and data migration vs BYTEA |
| **Database Design** | Timestamps                        | Timezone-aware timestamps (timestamptz)                           | Supports global operations, prevents confusion |
| **Frontend** | Input handling                    | Use refs for PII fields, not state                                | Enables explicit clearing, prevents re-render exposure |
| **Frontend** | Session security                  | Auto-clear PII after 5 minutes idle                               | Reduces exposure window, handles abandoned sessions |
| **Frontend** | Clipboard control                 | Disable copy/paste on PII fields                                  | Prevents leakage through clipboard managers |
| **Frontend** | Token storage                     | SessionStorage only, never localStorage                           | Auto-cleared on browser close, not persisted |
| **Compliance** | PCI DSS                           | Field-level encryption beyond TDE                                 | Meets PCI DSS 3.4 requirements for cardholder data |
| **Compliance** | GDPR                              | Support data portability and erasure                              | Enables right-to-access and right-to-be-forgotten |
| **Compliance** | Prohibited data                   | Never store CVV, PIN, or magstripe                                | PCI DSS requirement, reduces compliance scope |

This table captures all key design decisions that drive the security, performance, and compliance posture of the PII protection system.
