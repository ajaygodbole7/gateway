# PII/PCI Protection System Design
## Application-Layer Encryption Architecture

**Version:** 2.0  
**Audience:** Security Architects, System Architects, Senior Developers

---

## Executive Summary

This document outlines an architecture to render PII and PCI data cryptographically unreadable through application-layer encryption, protecting sensitive data at rest, in backups, and in logs—even from database administrators.

**Core Pattern:**
```
One PII Field → Three Database Columns
├─ encrypted_value: Base64([version|IV|ciphertext+tag])  // AES-256-GCM
├─ search_hash:     HMAC-SHA256(pepper, normalized_value) // Indexed equality search
└─ last_four:       "6789"                                // Masked display
```

**Key Decisions:**
- **Application-Layer Encryption:** Keys in Azure Key Vault, data in PostgreSQL—clean separation
- **Modern Algorithms:** AES-256-GCM (AEAD) and HMAC-SHA256 with secret pepper
- **Zero-Downtime Key Rotation:** Versioned ciphertext enables seamless key updates
- **Defense-in-Depth:** Encryption + guards + filters + sanitizers + immutable audit

**Compliance:** PCI DSS v4.0, GDPR Article 32, Gramm-Leach-Bliley Act

---

## 1. Problem Statement

### 1.1 Requirements

The system processes Social Security Numbers, bank account numbers, and payment card numbers. Data must be:

1. **Cryptographically unreadable** everywhere—databases, backups, logs, exports
2. **Searchable without decryption** for authorized operations
3. **Displayable masked** by default (`***-**-6789`)
4. **Evolvable** without service downtime or data rewrites

### 1.2 Threat Model

| Attack Vector | Defense |
|---------------|---------|
| Database breach | Keys external; database has only ciphertext |
| Insider threat (DBA) | DBAs cannot read plaintext without app access |
| Backup exposure | Backups encrypted; keys separate |
| Log leaks | Sanitizers redact before logging |
| API injection | Guards reject PII in URLs/headers |
| Accidental exposure | Filters block plaintext in responses |

### 1.3 Regulatory Frameworks

**PCI DSS v4.0:**
- **Req 3.5.1:** Render PAN unreadable using strong cryptography
- **Req 3.5.1.1:** Use keyed cryptographic hashes (HMAC, not simple hash)
- **Req 3.5.1.2:** Disk-level encryption insufficient alone
- **Req 3.6:** Document cryptographic architecture
- **Req 3.7:** Key management lifecycle processes
- **Req 10.1:** Audit all access to cardholder data

**GDPR Article 32:**
- Pseudonymization and encryption of personal data
- Appropriate technical measures (state-of-the-art)
- Ability to ensure ongoing confidentiality and integrity

**Gramm-Leach-Bliley Act (Safeguards Rule):**
- Implement information security program
- Encrypt customer information at rest and in transit
- Protect against unauthorized access
- Audit and monitor access to customer data

---

## 2. Design Rationale

### 2.1 Application-Layer vs Database Encryption

| Approach | Key Separation | Protects vs DBA | Field-Level | PCI DSS v4.0 | Decision |
|----------|---------------|----------------|-------------|--------------|----------|
| Database TDE | ❌ | ❌ | ❌ | ❌ (Fails 3.5.1.2) | Rejected |
| pgcrypto | ❌ | ❌ | ⚠️ | ❌ | Rejected |
| Application-layer | ✅ | ✅ | ✅ | ✅ | **Selected** |

**Why Application-Layer Wins:**
- Keys in Azure Key Vault, data in PostgreSQL (independent trust domains)
- Field-level encryption with AAD context binding
- Database vendor independence
- Directly satisfies PCI DSS 3.5.1.2 (disk encryption insufficient)
- Meets GLB Act requirements for protecting customer information

### 2.2 Three-Column Pattern Justification

| Pattern | Search | Display | Decrypt Rate | Decision |
|---------|--------|---------|--------------|----------|
| Encrypted only | Decrypt all | Decrypt | 100% | Rejected |
| Encrypted + Hash | Indexed | Decrypt | 90% | Rejected |
| Encrypted + Hash + Last4 | Indexed | No decrypt | <10% | **Selected** |

**Benefits:** 90%+ operations avoid decryption, meeting performance and security goals.

### 2.3 Algorithm Selection

**AES-256-GCM:**
- NIST-approved authenticated encryption (AEAD)
- Built-in integrity and authenticity
- Native AAD support for field binding
- Meets PCI DSS 3.5.1 strong cryptography requirement

**HMAC-SHA256 (not simple SHA-256):**
- **PCI DSS v4.0 Requirement 3.5.1.1:** Hashes must be keyed cryptographic hashes
- Secret pepper prevents rainbow table attacks
- Deterministic for equality search
- Key management in Azure Key Vault

---

## 3. Architecture

### 3.1 System Context

```
┌──────────┐  HTTPS  ┌────────────┐  TLS   ┌──────────┐
│  React   ├────────▶│ Spring Boot├───────▶│PostgreSQL│
│   SPA    │         │    API     │        │ Database │
└──────────┘         └──────┬─────┘        └──────────┘
                            │ HTTPS
                            ▼
                     ┌─────────────┐
                     │Azure Key    │
                     │Vault        │
                     └─────────────┘
```

### 3.2 Data Flow

**Write:**
```
Client → Guard validates → Service: Normalize → HMAC → Encrypt
                                   → Store (encrypted, hash, last4)
                                   → Audit
                                   → Filter validates
                                   → Return masked
```

**Search:**
```
Client → Normalize → HMAC → Query WHERE hash = ?
                          → Return last4 (no decrypt)
                          → Audit
```

**Decrypt (authorized):**
```
Authorization → Fetch encrypted → Parse version → Get key → Decrypt
                                                          → Audit
                                                          → Clear memory
```

---

## 4. Cryptographic Design

### 4.1 Encryption (PCI DSS 3.5.1)

**AES-256-GCM**
- Key: 256 bits
- IV: 96 bits (random per encryption)
- Tag: 128 bits (authentication)
- AAD: Field context `"{table}.{column}"`

### 4.2 Ciphertext Format (PCI DSS 3.7)

```
┌─────────┬─────────┬──────┬─────────────────┐
│Ver Len  │ Version │  IV  │ Ciphertext+Tag  │
│(1 byte) │(N bytes)│(12 B)│  (var + 16 B)   │
└─────────┴─────────┴──────┴─────────────────┘
```

**Example:** `[17][v2-prod-20241015][12 IV bytes][ciphertext][16 tag]`

**Benefits:** Self-describing, supports rotation, tamper-evident

### 4.3 AAD (Additional Authenticated Data)

**Format:** `"users.ssn"`, `"users.account_number"`, `"payment_methods.pan"`

**Security:** Cryptographically binds ciphertext to field. Prevents substitution attacks—copying ciphertext to different field fails decryption.

### 4.4 Search Hash (PCI DSS 3.5.1.1)

**CRITICAL: PCI DSS v4.0 requires keyed cryptographic hashes**

**Algorithm:** `Base64(HMAC-SHA256(pepper, normalized_value))`

**Not Simple Hash:** SHA-256 alone does NOT meet PCI DSS 3.5.1.1. Must use HMAC with secret pepper.

**Process:**
```
"123-45-6789" → Normalize: "123456789" → HMAC-SHA256(pepper, "123456789") → Base64 → Store
```

**Properties:**
- Deterministic (enables equality search)
- One-way (cannot reverse)
- Keyed (pepper prevents rainbow tables)
- Searchable via indexed column

**Limitations:** Equality only. No range queries, partial matching, or sorting.

### 4.5 Masked Display (PCI DSS 3.4.1)

**Storage:** Last 4 digits in separate column

**Format:** `***-**-6789`, `******5432`, `**** **** **** 1111`

**Benefit:** Display without decryption (90%+ operations)

---

## 5. Key Management (PCI DSS 3.6, 3.7)

### 5.1 Key Hierarchy

**Data Encryption Keys (DEK):**
- 256-bit AES keys
- Stored in Azure Key Vault
- Named: `pii-dek-{version}` (e.g., `pii-dek-v2-prod-20241015`)

**HMAC Pepper:**
- 512-bit secret
- Stored in Azure Key Vault
- Named: `pii-hmac-pepper-{version}`

**Access Control:**
- Azure Managed Identity
- Permissions: Get, List only (no Set, Delete, Purge)
- Least privilege principle

**Configuration:**
- Soft-delete: 90-day retention
- Purge protection: Enabled
- Network: Private endpoints
- Audit: All access logged

### 5.2 Key Rotation

**Zero-Downtime Process:**
```
1. Create new key version in Key Vault
2. Update app config (current-version=v3)
3. Rolling deployment
   ├─ New writes use v3
   └─ Old reads use v1, v2 (auto-detected from ciphertext)
4. Optional: Background re-encryption
```

**Benefits:** No interruption, old/new keys coexist, self-describing ciphertext

**Pepper Rotation:** More complex (requires re-hashing all data). Strategy: dual-read period, lazy migration.

---

## 6. Security Controls

### 6.1 Defense-in-Depth

| Layer | Control | Purpose |
|-------|---------|---------|
| L1 | Request Guards | Block PII in URLs/headers |
| L2 | Encryption | Render data unreadable |
| L3 | Response Filters | Block plaintext in output |
| L4 | Log Sanitizers | Redact from logs |
| L5 | Audit Log | Immutable access record |
| L6 | Access Controls | RBAC enforcement |

### 6.2 Request Guards (PCI DSS 3.4.2)

**Policy:** No PII in HTTP URLs or custom headers

**Rationale:** URLs logged by proxies, gateways, browsers, analytics

**Enforcement:** Pattern detection, HTTP 400 rejection, require POST body

### 6.3 Response Filters (PCI DSS 3.4.1)

**Policy:** No plaintext PII fields in responses

**Enforcement:** Parse JSON, reject forbidden fields (`ssn`, `accountNumber`, `pan`), allow only masked (`ssnMasked`)

### 6.4 Log Sanitizers

**Policy:** No PII in logs

**Scope:** Application logs, exceptions, MDC, SQL logs

**Redaction:** Replace patterns (`***-**-****`, `**********`)

### 6.5 Immutable Audit (PCI DSS 10.1)

**Schema:**
```sql
timestamp, user_id, action, entity_type, entity_id, 
fields_accessed[], purpose, outcome
```

**Immutability:** PostgreSQL rules prevent UPDATE/DELETE

**Critical:** Never log actual PII values—only access metadata

---

## 7. Data Model

### 7.1 Schema

```sql
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    
    -- Three-column pattern
    ssn_encrypted_value TEXT,
    ssn_search_hash VARCHAR(64),
    ssn_last_four VARCHAR(4),
    
    account_number_encrypted_value TEXT,
    account_number_search_hash VARCHAR(64),
    account_number_last_four VARCHAR(4),
    
    pan_encrypted_value TEXT,
    pan_search_hash VARCHAR(64),
    pan_last_four VARCHAR(4),
    
    CONSTRAINT users_ssn_hash_unique UNIQUE (ssn_search_hash)
);

-- Index hash columns for search
CREATE INDEX idx_users_ssn_hash ON users(ssn_search_hash);
```

### 7.2 Column Rationale

| Column | Type | Purpose | Indexed |
|--------|------|---------|---------|
| `*_encrypted_value` | TEXT | Ciphertext with version | No |
| `*_search_hash` | VARCHAR(64) | HMAC for search | Yes |
| `*_last_four` | VARCHAR(4) | Masked display | No |

---

## 8. Compliance Mapping

### 8.1 PCI DSS v4.0

| Requirement | Implementation |
|-------------|----------------|
| **3.5.1** Render PAN unreadable | AES-256-GCM |
| **3.5.1.1** Keyed cryptographic hashes | HMAC-SHA256 with pepper |
| **3.5.1.2** Disk encryption insufficient | Application-layer encryption |
| **3.6** Cryptographic architecture | This document |
| **3.7** Key management | Azure Key Vault with versioning |
| **10.1** Audit access | Immutable audit log |

### 8.2 GDPR Article 32

| Requirement | Implementation |
|-------------|----------------|
| Pseudonymization | HMAC hashing separates identifier |
| Encryption | AES-256-GCM with external keys |
| Confidentiality & integrity | AEAD provides both |
| Breach notification support | Audit logs for forensics |

### 8.3 Gramm-Leach-Bliley Act

| Requirement | Implementation |
|-------------|----------------|
| Information security program | This design + operational procedures |
| Encrypt customer information | AES-256-GCM for all PII |
| Protect unauthorized access | Keys in Key Vault, access controls, audit |
| Monitor access | Immutable audit log |

---

## 9. Design Validation

| Area | Check | Status |
|------|-------|:------:|
| **Cryptography** | NIST-approved algorithms | ✅ |
| | Random IV per encryption | ✅ |
| | AAD context binding | ✅ |
| | Keyed hashes (HMAC, not SHA-256 alone) | ✅ |
| **Key Management** | External to database | ✅ |
| | Zero-downtime rotation | ✅ |
| | Least privilege access | ✅ |
| | Documented lifecycle | ✅ |
| **Data Protection** | Three-column optimization | ✅ |
| | HMAC with secret pepper | ✅ |
| | Masked display | ✅ |
| **Defense-in-Depth** | Independent layers | ✅ |
| | Request guards | ✅ |
| | Response filters | ✅ |
| | Log sanitizers | ✅ |
| | Immutable audit | ✅ |
| **Compliance** | PCI DSS v4.0 | ✅ |
| | GDPR Article 32 | ✅ |
| | Gramm-Leach-Bliley Act | ✅ |

---

## Appendix: Glossary

| Term | Definition |
|------|------------|
| **AAD** | Additional Authenticated Data - context bound to ciphertext |
| **AEAD** | Authenticated Encryption with Associated Data |
| **DEK** | Data Encryption Key - 256-bit AES key in Key Vault |
| **GCM** | Galois/Counter Mode - AEAD for AES |
| **HMAC** | Hash-based Message Authentication Code - keyed hash |
| **IV** | Initialization Vector - random per encryption |
| **Pepper** | Secret key for HMAC - prevents rainbow tables |
| **PII** | Personally Identifiable Information |

---

**Document Status:** Design Approved  
**Compliance:** PCI DSS v4.0, GDPR Article 32, Gramm-Leach-Bliley Act
