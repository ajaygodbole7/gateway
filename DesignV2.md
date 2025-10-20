# PII/PCI Protection System Design
## Application-Layer Encryption Architecture


## Executive Summary

This document outlines an architecture to render PII (Personally Identifiable Information) and PCI (Payment Card Industry) data cryptographically unreadable through application-layer encryption. This approach protects sensitive data at rest, in backups, in logs, and from unauthorized access by privileged users like database administrators.

**Core Pattern:** A single sensitive data field is stored across three distinct database columns to balance security, performance, and functionality.

```
One PII Field → Three Database Columns
├─ encrypted_value: Base64([version|IV|ciphertext+tag])  // AES-256-GCM
├─ search_hash:     HMAC-SHA256(pepper, normalized_value) // Indexed for equality search
└─ last_four:       "6789"                                // Masked for safe display
```

**Key Design Decisions:**
- **Application-Layer Encryption:** Establishes a clean separation of concerns by managing cryptographic keys in a dedicated Key Management Service (KMS), external to the database where the encrypted data resides.
- **Modern & Secure Algorithms:** Utilizes **AES-256-GCM** for authenticated encryption and **HMAC-SHA256** for deterministic, keyed hashing to enable secure searches.
- **Zero-Downtime Key Rotation:** Implements a versioned ciphertext format, allowing cryptographic keys to be rotated without service interruption or complex data migrations.
- **Defense-in-Depth:** Complements encryption with multiple independent security controls, including request guards, response filters, log sanitizers, and an immutable audit trail.

**Compliance Alignment:** This design directly supports compliance with major regulations, including **PCI DSS 3.2.1 (Req 3.4, 3.5, 10.1)** and **GDPR (Article 32)**.

---

## 1. Problem Statement & Requirements

### 1.1. Protection Scope

The system processes highly sensitive data, including Social Security Numbers (SSNs), bank account numbers, and payment card numbers (PANs). This data must be protected according to the following requirements:
1.  **Cryptographically Unreadable:** Data must be unreadable everywhere it is stored, including primary databases, backups, exports, and logs.
2.  **Searchable Without Decryption:** Authorized users (e.g., customer service) must be able to search for specific records without decrypting the entire dataset.
3.  **Safely Displayable:** The UI must display data in a masked format by default (e.g., `***-**-6789`) for most operations.
4.  **Evolvable & Maintainable:** The cryptographic system must be able to evolve over time (e.g., key rotation) without requiring service downtime.

### 1.2. Threat Model

This design mitigates the following key threats:

| Attack Vector                             | Defense Strategy                                                                 |
| ----------------------------------------- | -------------------------------------------------------------------------------- |
| **External Database Breach**              | Data is encrypted. Keys are stored externally in a KMS (e.g., Azure Key Vault).  |
| **Insider Threat (e.g., Malicious DBA)**  | DBAs have access to ciphertext but not the keys required for decryption.         |
| **Backup Media Exposure**                 | Backups contain only encrypted data, rendering them useless without the keys.   |
| **Sensitive Data in Logs**                | Pattern-based sanitizers redact PII from logs before they are written to disk.   |
| **PII in URLs/Headers**                   | Request guards reject any requests containing PII patterns in URLs or headers.   |
| **Accidental API Exposure**               | Response filters block any API responses that accidentally contain plaintext PII. |

**Out of Scope:** This design focuses on application and data-level security. It assumes that underlying host security, KMS security, and protection against quantum attacks are managed by the cloud provider and future architectural reviews.

---

## 2. Design Rationale & Principles

### 2.1. Why Application-Layer Encryption?

Database-level Transparent Data Encryption (TDE) protects data on disk but is often transparent to the database engine itself, meaning a DBA with query access can still see plaintext data. Application-layer encryption solves this by establishing two distinct trust domains.

| Approach                  | Key Separation                  | Protects Against DBA Access | Field-Level Control | Decision     |
| ------------------------- | ------------------------------- | --------------------------- | ------------------- | ------------ |
| Database TDE              | ❌ (Keys often managed by DB)   | ❌ (Transparent to DBA)     | ❌ (Whole database) | **Rejected** |
| **Application-Layer**     | ✅ (Keys in external KMS)       | ✅ (DBA sees only ciphertext) | ✅ (Per field)      | **Selected** |

By handling encryption in the application, we ensure that plaintext data only exists within the trusted application runtime, providing superior protection and direct compliance with regulations requiring data to be "rendered unreadable."

### 2.2. The Three-Column Pattern

Storing a single piece of PII across three columns is a pragmatic trade-off that optimizes for performance and security.

| Pattern                    | Search Performance        | Display Operation | Decision     |
| -------------------------- | ------------------------- | ----------------- | ------------ |
| Encrypted Value Only       | ❌ (Full table scan + decrypt) | Requires decryption | **Rejected** |
| **Encrypted + Hash + Last4** | ✅ (Fast, indexed search) | ✅ (No decryption)  | **Selected** |

This pattern eliminates the need for costly decryption operations in over 90% of use cases (search and display), justifying the moderate increase in storage overhead.

### 2.3. Algorithm Selection

- **AES-256-GCM:** Chosen for its status as a modern, efficient, and secure **Authenticated Encryption with Associated Data (AEAD)** cipher. It provides both confidentiality (encryption) and integrity/authenticity (a built-in MAC tag) in a single, well-vetted primitive.
- **HMAC-SHA256:** Chosen for creating the searchable hash. It is a deterministic, keyed hashing function. "Deterministic" means the same input always produces the same output, enabling equality lookups. "Keyed" (with a secret "pepper") means the hashes are protected against rainbow table attacks.

---

## 3. System Architecture

### 3.1. System Context Diagram

```
┌──────────────────┐      HTTPS      ┌──────────────────────┐      TLS      ┌──────────────────┐
│   Client (SPA)   ├────────────────▶│   Spring Boot API    ├──────────────▶│   PostgreSQL DB  │
└──────────────────┘                 │ (Application Layer)  │               │ (Encrypted Data) │
└──────────┬───────────┘               └──────────────────┘
│ HTTPS
▼
┌──────────────────────┐
│ Azure Key Vault (KMS)│
│   (Encryption Keys)  │
└──────────────────────┘
```

### 3.2. Data Flow for a Write Operation

1.  **Client:** The client POSTs sensitive data (e.g., an SSN) in the body of an HTTPS request.
2.  **Request Guard:** The API gateway or a middleware layer validates that no PII is present in the URL or headers.
3.  **Service Layer:** The application service receives the plaintext data.
4.  **Encryption Service:**
    a. **Normalize:** The plaintext is normalized (e.g., `(555)-123-4567` becomes `5551234567`).
    b. **Extract Last4:** The last four digits are extracted for the `*_last_four` column.
    c. **Generate Hash:** The normalized value is hashed using HMAC-SHA256 with a secret pepper to create the `*_search_hash`.
    d. **Encrypt:** The normalized value is encrypted using AES-256-GCM. The encryption key is fetched from the KMS.
5.  **Database:** The three resulting values (`encrypted_value`, `search_hash`, `last_four`) are stored in the database.
6.  **Audit Log:** An immutable audit event is created, recording who accessed the data and for what purpose, without logging the data itself.
7.  **Response Filter:** The API response is filtered to ensure no plaintext PII is accidentally returned. The client receives a confirmation, typically with the masked value.

---

## 4. Detailed Cryptographic Design

### 4.1. Ciphertext Format

To support zero-downtime key rotation, the encrypted payload is self-describing.

`Base64 ( [Version Length (1 byte)] [Key Version (N bytes)] [IV (12 bytes)] [Ciphertext + Auth Tag (Variable)] )`

- **Version:** A string identifying the key used for encryption (e.g., `v1-prod-20241015`). This allows the decryption service to fetch the correct key.
- **IV (Initialization Vector):** A unique, randomly generated nonce (12 bytes for GCM) for each encryption operation.
- **Ciphertext + Auth Tag:** The output of the AES-GCM encryption process.

### 4.2. Additional Authenticated Data (AAD)

AAD binds the ciphertext to its context, preventing substitution attacks.

- **Format:** `"{table_name}.{column_name}"` (e.g., `"users.ssn"`)
- **Security Property:** This AAD string is fed into the AES-GCM algorithm. If an attacker copies ciphertext from `users.ssn` to `users.bank_account`, decryption will fail because the AAD will not match.

### 4.3. Search Hash Normalization

A consistent normalization strategy is critical for the search hash to function correctly.

- **Rule:** All non-numeric characters should be removed from the input value before it is passed to the HMAC function.
- **Example:** `(555)-123-4567` and `555.123.4567` both normalize to `5551234567`, ensuring they produce the same search hash.

### 4.4. In-Memory Data Handling

Plaintext data should exist in memory for the shortest possible duration.
- **Recommendation:** Use mutable data types (e.g., `char[]` or `byte[]` in Java) for handling plaintext. These can be explicitly zeroed out in a `finally` block after use, unlike immutable `String` objects.

---

## 5. Key Management

### 5.1. Key Hierarchy & Storage

- **Data Encryption Keys (DEKs):** 256-bit AES keys used for data encryption. Stored as versioned secrets in Azure Key Vault.
- **HMAC Pepper:** A 512-bit (or stronger) secret used for the keyed hash. Stored as a separate, versioned secret in Key Vault.
- **Access Control:** The application uses a Managed Identity with least-privilege access (`Get` and `List` permissions only) to the keys in Key Vault.

### 5.2. Zero-Downtime Key Rotation

1.  **Provision New Key:** A new DEK version is created in Key Vault (e.g., `pii-dek-v2`).
2.  **Update Application Config:** The application's configuration is updated to point to the new key version (`v2`) for all new encryption operations.
3.  **Deploy:** The application is deployed.
    - **New Writes:** All new data is encrypted with `v2`.
    - **Reads:** When decrypting data, the application reads the version from the ciphertext payload. If it sees `v1`, it requests the `v1` key; if it sees `v2`, it requests the `v2` key.
4.  **(Optional) Background Migration:** A background job can be run to slowly re-encrypt old `v1` data with the new `v2` key.

---

## 6. Defense-in-Depth Controls

Encryption is the core control, but it is supported by multiple independent layers.

| Layer                | Control                  | Purpose                                                                   |
| -------------------- | ------------------------ | ------------------------------------------------------------------------- |
| **L1: Ingress**      | **Request Guards**       | Block PII in URLs and headers to prevent leakage into proxy/gateway logs. |
| **L2: Application**  | **Encryption Service**   | Render data unreadable at the core of the application.                    |
| **L3: Egress**       | **Response Filters**     | Prevent plaintext PII from being accidentally returned in API responses.  |
| **L4: Observability**| **Log Sanitizers**       | Redact PII patterns from all application logs before they are written.    |
| **L5: Accountability**| **Immutable Audit Log**  | Create a tamper-evident record of all access to sensitive data.           |

---

## 7. Data Model

### 7.1. Database Schema Example

```sql
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    -- Non-sensitive fields
    email VARCHAR(255) NOT NULL UNIQUE,
    
    -- Three-column pattern for an optional SSN field
    ssn_encrypted_value TEXT NULL,
    ssn_search_hash VARCHAR(64) NULL,
    ssn_last_four VARCHAR(4) NULL,

    -- Enforce uniqueness on the hash for non-NULL values
    CONSTRAINT users_ssn_search_hash_unique UNIQUE (ssn_search_hash)
);

-- Index the hash column for fast lookups
CREATE INDEX idx_users_ssn_search_hash ON users(ssn_search_hash) 
  WHERE ssn_search_hash IS NOT NULL;
```

---

## 8. Design Validation Checklist

| Area                  | Check                                                    | Status |
| --------------------- | -------------------------------------------------------- | :----: |
| **Cryptography**      | NIST-approved algorithms (AES-GCM, HMAC-SHA256)          |   ✅   |
|                       | Random IV per encryption                                 |   ✅   |
|                       | AAD used for context binding                             |   ✅   |
| **Key Management**    | Keys are external to the database                        |   ✅   |
|                       | Zero-downtime rotation is supported                      |   ✅   |
|                       | Access via least-privilege Managed Identity              |   ✅   |
| **Data Protection**   | Three-column pattern minimizes decryption                |   ✅   |
|                       | HMAC is keyed with a secret pepper                       |   ✅   |
|                       | PII normalization strategy is defined                    |   ✅   |
| **Defense-in-Depth**  | Independent controls for ingress, egress, and logging    |   ✅   |
|                       | Immutable audit trail is in place                        |   ✅   |
| **Compliance**        | Supports PCI DSS 3.4, 3.5, 10.1 & GDPR Art. 32           |   ✅   |
```
