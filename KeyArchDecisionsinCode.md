### Architectural Decisions and Code Implementation

### 1. Security & Authentication Architecture

#### Decision: Implement the "Zero Trust" Security Pattern

This is the foundational security posture of the Security Gateway. It mandates that no sensitive credentials, especially JWTs (ID, Access, or Refresh tokens), are ever stored on the client-side. The Security Gateway manages all tokens server-side.

*   **Rationale:** To eliminate the entire class of Cross-Site Scripting (XSS) attacks that target JWTs stored in the browser, a primary attack vector for modern web applications.
*   **Realized In:** The `SessionService` persists session data server-side. The `SessionAuthenticationFilter` and `CookieUtil` ensure that only an opaque, `HttpOnly` session cookie is ever exposed to the client's browser.

---
#### Decision: Adhere Strictly to the OIDC Authorization Code Flow with PKCE
The gateway implements the most secure, industry-standard flow for browser-based user authentication (RFC 7636).

*   **Rationale:** To prevent Cross-Site Request Forgery (CSRF) attacks on the callback endpoint and to mitigate authorization code interception, where a stolen `code` is rendered useless without the corresponding secret `code_verifier`.
*   **Realized In:** The `OAuth2Service` class manages the entire PKCE handshake.

---
#### Decision: Centralize Secret Management in Azure Key Vault with Managed Identity
All application secrets are stored externally and securely in Azure Key Vault.

*   **Rationale:** To prevent sensitive credentials from ever being committed to source control, providing a single, auditable, and highly secure point of management.
*   **Realized In:** The `AzureKeyVaultClient` is the sole interface for retrieving secrets. It is authenticated via the `ManagedIdentityTokenProvider`, which leverages Azure's built-in identity features.

---
#### Decision: Selectively Encrypt Only the ID Token Within the Session Data
Only the most sensitive field, the `idToken`, is encrypted before being stored. All other session metadata (e.g., `userId`) is stored in plaintext.

*   **Rationale:** This strategy provides an optimal balance of security and performance. It strongly protects the sensitive identity claims while allowing for high-performance access to non-sensitive metadata for common operations like session invalidation, avoiding the expensive cryptographic overhead of full-object decryption on every access.
*   **Realized In:** The `SessionService` uses the `EncryptionService` to encrypt *only* the `plaintextIdToken`. The `SessionAuthenticationFilter` later decrypts this specific field before validation.

---
#### Decision: Implement Multiple Layers of Security Header Defenses
A comprehensive set of security-related HTTP headers are sent on every response to instruct the browser to enforce strict client-side security policies.

*   **Rationale:** To provide defense-in-depth against a wide range of common web vulnerabilities, including clickjacking (`X-Frame-Options`), protocol downgrade attacks (`Strict-Transport-Security`), and content injection attacks (`Content-Security-Policy`).
*   **Realized In:** The `SecurityConfig` class meticulously configures a wide range of security headers to be applied to all HTTP responses served by the gateway.

---
### 2. Session Management & Scalability Architecture

#### Decision: Use Centralized, Server-Side Session Storage in Redis
To support horizontal scaling and maintain a stateless application tier, all user session data is stored externally in a shared Redis cluster.

*   **Rationale:** Allows the gateway to be scaled out easily. If an instance fails, user sessions are not lost and can be immediately served by another healthy instance, ensuring high availability.
*   **Realized In:** The `SessionService` uses a `RedisTemplate` for all session operations.

---
#### Decision: Employ Redis Hashes to Enable the Selective Encryption Strategy
The session is stored as a Redis Hash (`HSET`) rather than a single string.

*   **Rationale:** This data structure is the key technical enabler for the selective encryption strategy. It allows the session to be stored as a collection of individual fields under a single key (`session:{sessionId}`), making it possible to read non-sensitive fields like `userId` directly and efficiently without having to fetch and decrypt the entire session object.
*   **Realized In:** The `SessionService` was specifically implemented to use `redisTemplate.opsForHash()` for all its operations.

---
#### Decision: Generate Cryptographically Secure and Opaque Session Identifiers
The `sessionId` stored in the user's cookie is a high-entropy, unpredictable string with 256 bits of randomness.

*   **Rationale:** This is a mandatory security measure to make it computationally infeasible for an attacker to guess a valid session ID and hijack a user's session.
*   **Realized In:** The `SessionService` contains a private `generateSessionId` method that uses `java.security.SecureRandom`.

---
#### Decision: Ensure Horizontal Scalability with a Centralized M2M Token Manager
To handle tasks for the gateway's own identity (M2M tokens), a dedicated, centralized service manages the acquisition, caching, and refresh logic for all IdPs.

*   **Rationale:** To prevent "thundering herd" problems and race conditions in a scaled-out environment. This centralizes the complex logic of M2M token management, ensuring that caching and distributed locking are applied universally and consistently for all M2M token types.
*   **Realized In:**
    *   **`M2MTokenManagerService.java`**: This service is the single source of truth for all M2M tokens. It uses a shared Redis cache for the tokens.
    *   **`DistributedLockService.java`**: Provides the underlying distributed lock used by the `M2MTokenManagerService` to ensure only one instance at a time performs a token fetch from an IdP.

---
### 3. Multi-IdP and Real-Time Validation Architecture

#### Decision: Adopt a "Refresh-on-Use" Real-Time Token Validation Model
Every incoming API request triggers a synchronous validation call to the appropriate Identity Provider.

*   **Rationale:** This was a mandatory project requirement that prioritizes absolute real-time validation of a user's status over minimizing latency.
*   **Realized In:** The `SessionAuthenticationFilter` orchestrates a flow where it decrypts the stored token and calls a dedicated validation service on every request. If a new token is returned, the filter updates the session in Redis.

---
#### Decision: Support Multiple Identity Providers via a Stored Provider Enum
The gateway handles tokens from different issuers by inspecting a stored `IdpProvider` enum within the session data itself.

*   **Rationale:** This is a performance and clarity enhancement. By storing the authenticating provider at session creation, we avoid parsing the JWT's `iss` claim on every request. The routing logic becomes a faster and more explicit `switch` statement.
*   **Realized In:** An `IdpProvider` enum was created. The `SessionData` record and `SessionService` were updated to include it. The `SessionAuthenticationFilter`'s core logic now uses a `switch` statement on this enum to route to the correct validation service.

---
#### Decision: Create Separate, Dedicated Services for User Token Validation
Instead of a single service with complex conditional logic, two distinct services were created: `PingTokenValidationService` and `EntraTokenValidationService`.

*   **Rationale:** This adheres to the Single Responsibility Principle. "Validation" was chosen as a clearer name than "Introspection." Each service is an expert on communicating with its specific IdP, and each correctly uses the centralized `M2MTokenManagerService` to authenticate itself, thereby preventing race conditions and separating concerns.
*   **Realized In:** The `PingTokenValidationService` and `EntraTokenValidationService` classes were created. They are injected into the `SessionAuthenticationFilter` for use in the validation routing logic.

---
### 4. Resilience & Application Operations

#### Decision: Implement Robust Resilience with Circuit Breakers on All External Calls
All critical external network calls are wrapped in a Resilience4j circuit breaker.

*   **Rationale:** To protect the gateway from being slowed down or crashed by an unresponsive downstream dependency. It allows the system to "fail fast" and "fail closed" securely.
*   **Realized In:** The `application.yml` file contains declarative configuration for all circuit breakers. The `AzureKeyVaultClient`, `M2MTokenManagerService`, `PingTokenValidationService`, and `EntraTokenValidationService` classes use the `@CircuitBreaker` annotation.

---
#### Decision: Enforce a "Fail-Fast" Startup with Configuration Validation
The application will refuse to start if its critical configuration properties are missing or malformed.

*   **Rationale:** Prevents the gateway from running in an insecure or non-functional state due to deployment errors.
*   **Realized In:** The `ConfigurationValidator` class implements `InitializingBean` and runs on application startup to validate all required properties.

---
#### Decision: Optimize Network Latency with a Shared and Tuned HTTP Client
A shared, high-performance `OkHttpClient` instance is used for all outbound traffic, configured with connection pooling and HTTP/2 support.

*   **Rationale:** To minimize the latency of external calls by reusing existing "warm" connections (avoiding TCP/TLS handshake overhead) and leveraging the multiplexing capabilities of HTTP/2.
*   **Realized In:** The `HttpClientConfig` class creates a shared `ConnectionPool` and `Dispatcher` and configures all `OkHttpClient` beans to use them.
