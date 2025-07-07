# Security Gateway: Implementation Reference


## Key Patterns
- **Zero Trust**: No client-side tokens, only `HttpOnly` session cookies
- **PKCE OAuth**: Full RFC 7636 implementation
- **Multi-IdP Support**: Ping Identity + Microsoft Entra support
- **Time to React - Real-time User Validation**: Every API request validates with IdP
- **Distributed M2M**: Shared token management with leader election

### Critical Classes
```
SessionAuthenticationFilter  - Request authentication entry point
OAuth2Service               - PKCE flow orchestration  
M2MTokenManagerService      - Gateway credential management
SessionService              - Redis session operations
```

## Architecture Decisions

### 1. Token Storage Strategy

**Client Side**: Zero tokens
```java
// Only this cookie exists on client
Cookie: GATEWAY_SESSION=q_xT9z...8LpW_g; HttpOnly; Secure; SameSite=Strict
```

**Server Side**: Redis Hash Structure
```java
session:{sessionId} → {
  userId: "user-123",
  idToken: "encrypted_base64_blob",    // Only this field encrypted
  provider: "PING_IDENTITY",           // Fast routing without JWT parsing
  createdAt: 1677610000,
  clientFingerprint: "hash..."
}
```

### 2. M2M Token Lifecycle

**Storage Pattern**
```java
// Redis key structure
m2m_token:PING_IDENTITY → {
  "tokenProvider": "PING_IDENTITY",
  "accessToken": "eyJhbG...",
  "expiresAt": "2024-01-01T12:00:00Z"
}
```

**Acquisition Flow**
```java
// 1. Check cache
String token = redis.get("m2m_token:PING_IDENTITY");
if (fresh) return token;

// 2. Distributed lock (only one instance fetches)
if (acquireLock("lock:m2m_token:PING_IDENTITY")) {
    token = fetchFromIdP();
    redis.set("m2m_token:PING_IDENTITY", token, ttl);
    releaseLock();
}

// 3. Followers wait and read from cache
return redis.get("m2m_token:PING_IDENTITY");
```


### 3. Request Flow Summary
**User Authentication Flow**

1. User request → `SessionAuthenticationFilter`
2. Extract session from cookie → Fetch from Redis
3. Decrypt ID token → Route to appropriate User Token validation service
4. User Token Validation service requests M2M token → `M2MTokenManagerService`
5. M2M token retrieved/refreshed from Redis
6. Validate user token with IdP using M2M token
7. Update session if needed → Continue request

**M2M Token Refresh Flow**

1. Check Redis cache: `GET m2m_token:PROVIDER`
2. If stale/missing → Acquire distributed lock
3. Leader fetches new token from IdP
4. Store in Redis → Release lock
5. Return token to caller

## Redis Performance Strategy

### Data Structure Choices

| Use Case | Structure | Rationale |
|----------|-----------|-----------|
| **Sessions** | Hash | Field-level access, selective encryption |
| **M2M Tokens** | String | Simple key-value, TTL support |
| **Distributed Locks** | String + NX | Atomic lock acquisition |
| **User Session Index** | Set | Fast membership, bulk logout |
| **Failed Logins** | String + INCR | Atomic counters with TTL |

### Why Hashes for Sessions

```java
// Memory: ~5x more efficient than separate keys
session:abc123 → Hash (30 bytes overhead for all fields)
vs
session:abc123:* → Multiple keys (90 bytes overhead each)

// Performance: Selective field access
String userId = redis.hget("session:abc123", "userId");  // No decryption needed
String token = redis.hget("session:abc123", "idToken");  // Decrypt only when used

// Atomicity: Update single fields
redis.hset("session:abc123", "lastAccess", timestamp);   // No race conditions
```

### Optimization Techniques

**Pipeline for Batch Operations**
```java
List<Object> results = redisTemplate.executePipelined(connection -> {
    connection.hGet(key, "userId");
    connection.hGet(key, "idToken");
    connection.hGet(key, "provider");
    return null;
});
```

**Key Design for Clustering**
```java
// Hash tags ensure related data on same shard
session:{user123}:abc → Same shard as
user_sessions:{user123} → Same shard as
auth:failures:{user123} → Enables multi-key ops
```

## Concurrency Deep Dive

### M2M Token Refresh Concurrency

**The Problem**: Multiple gateway instances(horizontal scaling) need M2M tokens simultaneously
```
Instance A: Token expired, needs refresh ─┐
Instance B: Token expired, needs refresh ─┼─> Thundering herd
Instance C: Token expired, needs refresh ─┘
```

**The Solution**: Distributed Lock with Leader Election

```java
// M2MTokenManagerService.refreshTokenWithLock()
private String refreshTokenWithLock(IdpProvider provider) {
    String lockKey = "lock:m2m_token:" + provider.name();
    String lockToken = lockService.tryAcquireLock(lockKey, Duration.ofSeconds(20));
    
    if (lockToken == null) {
        // FOLLOWER PATH: Someone else is leader
        return waitForLeaderAndRetry(provider);
    }
    
    try {
        // LEADER PATH: I won the lock
        // Double-check cache (another instance might have refreshed)
        M2MToken token = getFreshTokenFromCache(provider);
        if (token != null) {
            return token.accessToken();
        }
        
        // Actually fetch new token
        return performRefresh(provider);
    } finally {
        lockService.releaseLock(lockKey, lockToken);
    }
}
```

**Follower Retry Logic**
```java
@Retryable(
    value = TokenException.class,
    maxAttemptsExpression = "${app.m2m.retry.max-attempts:15}",
    backoff = @Backoff(delayExpression = "${app.m2m.retry.delay-ms:300}")
)
private String waitForLeaderAndRetry(IdpProvider provider) {
    // Follower waits 300ms between attempts
    // After ~4.5 seconds (15 * 300ms), gives up
    M2MToken token = getFreshTokenFromCache(provider);
    if (token != null) {
        return token.accessToken();
    }
    throw new TokenException("Token not yet available");
}
```

**Proactive Background Refresh**
```java
@Scheduled(fixedRate = 60000) // Every minute
public void proactiveRefreshAllTokens() {
    for (IdpProvider provider : IdpProvider.values()) {
        M2MToken cached = getFreshTokenFromCache(provider);
        if (cached == null || cached.expiresWithin(Duration.ofMinutes(5))) {
            // Refresh tokens expiring in < 5 minutes
            refreshTokenWithLock(provider);
        }
    }
}
```

### User ID Token Validation Concurrency

**Challenge**: Every API request must validate user's ID token with IdP

**Concurrent Request Handling**
```java
// Multiple requests for same user can execute simultaneously
Request 1: User ABC → Validate token → IdP call ─┐
Request 2: User ABC → Validate token → IdP call ─┼─> Parallel validation
Request 3: User ABC → Validate token → IdP call ─┘
```

**No Caching Strategy** (Security > Performance)
```java
// SessionAuthenticationFilter - Each request validates independently
public class SessionAuthenticationFilter extends OncePerRequestFilter {
    
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response,
                                  FilterChain chain) {
        // 1. Extract session
        String sessionId = extractSessionId(request);
        SessionData session = sessionService.getSession(sessionId);
        
        // 2. Decrypt ID token
        String idToken = encryptionService.decrypt(session.encryptedIdToken());
        
        // 3. Validate with IdP (EVERY request)
        // No caching = No stale user state
        TokenValidationResult result = validateWithIdP(session.provider(), idToken);
        
        if (!result.valid()) {
            response.sendError(401);
            return;
        }
        
        // 4. Update session if token refreshed
        if (result.hasNewToken()) {
            updateSessionToken(sessionId, result.newToken());
        }
        
        chain.doFilter(request, response);
    }
}
```

**Session Update Race Conditions**

When IdP returns a refreshed token, multiple concurrent requests might try to update:

```java
// SessionService handles concurrent updates
public void updateSessionToken(String sessionId, String newToken) {
    // Redis operations are atomic
    String encryptedToken = encryptionService.encrypt(newToken);
    
    // HSET is atomic - last write wins
    redisTemplate.opsForHash().put(
        "session:" + sessionId,
        "idToken",
        encryptedToken
    );
    
    // Update timestamp atomically
    redisTemplate.opsForHash().put(
        "session:" + sessionId,
        "lastTokenUpdate",
        System.currentTimeMillis()
    );
}
```

**Why "Last Write Wins" is Safe**
```
Time T1: Request A validates, gets new token (expires at T+15min)
Time T2: Request B validates, gets new token (expires at T+15min)
Time T3: Request C validates, gets new token (expires at T+15min)

All tokens are valid and fresh - order doesn't matter
```


## Configuration Reference

Uses Spring Properties `ApplicationProperties`
Fail-fast if properties are not valid

```yaml
app:
  auth:
    ping:
      client-id: ${PING_CLIENT_ID}
      token-uri: ${PING_TOKEN_URI}
    entra:
      authority: ${ENTRA_AUTHORITY}
      client-id: ${ENTRA_CLIENT_ID}
  security:
    session:
      sliding-window-minutes: 30
      absolute-timeout-hours: 8
  m2m:
    refresh:
      rate: 60000  # 1 minute
    retry:
      max-attempts: 15
      delay-ms: 300
```
### Performance Optimizations

#### Connection Pooling

```java
// Shared across all HTTP calls
ConnectionPool pool = new ConnectionPool(
    20,     // max idle
    5,      // keep alive  
    TimeUnit.MINUTES
);

OkHttpClient client = new OkHttpClient.Builder()
    .connectionPool(pool)
    .protocols(Arrays.asList(Protocol.HTTP_2, Protocol.HTTP_1_1))
    .build();
````

#### Virtual Threads (Java 21)

```java
// Enabled for @Async and @Scheduled
@Bean
public AsyncTaskExecutor applicationTaskExecutor() {
    return new TaskExecutorAdapter(
        Executors.newVirtualThreadPerTaskExecutor()
    );
}
```

#### Security Headers

```java
// Applied to all responses
.headers(headers -> headers
    .frameOptions(frame -> frame.deny())
    .httpStrictTransportSecurity(hsts -> hsts
        .maxAgeInSeconds(365 * 24 * 60 * 60)
        .includeSubDomains(true)
        .preload(true))
    .contentSecurityPolicy(csp -> csp
        .policyDirectives("default-src 'self'; ..."))
)
```

### Failure Scenarios

* **IdP Unavailable**

    * Circuit breaker opens after threshold
    * Requests fail fast with 503
    * No stale tokens served (security > availability)

* **Redis Down**

    * Sessions unreadable → 401 responses
    * M2M tokens unretrievable → service degraded
    * Health checks fail → removed from load balancer

* **Key Vault Inaccessible**

    * Startup fails (fail-fast principle)
    * Running instances continue with cached secrets
    * Circuit breaker prevents cascading failures

```
```
###  Resilience Patterns

#### Circuit Breakers
- **Library:** Resilience4j with `@CircuitBreaker` annotations
- **Configuration:** Declared in `application.yml`
- **Coverage:** All external calls (Key Vault, IdP services)

#### HTTP Client Optimization
- **Implementation:** Shared `OkHttpClient` with connection pooling
- **Features:** HTTP/2 support, connection reuse
- **Configuration:** `OkHttpClientConfig` class

## Critical Invariants

1. **Session cookies never contain tokens**
2. **M2M tokens are gateway credentials, not user tokens**
3. **Every request validates with IdP (no caching user tokens)**
4. **Circuit breakers fail closed (deny on error)**
5. **Distributed locks prevent token refresh races**
6. **Only one instance refreshes M2M token at a time**
7. **User token validation happens in parallel (no locking)**
8. **Session updates are atomic (last write wins)**
9. **Redis hashes optimize memory and enable selective field access**
10. **Pipeline operations reduce network round trips**
11. **All external API calls must use the right OkHttpClient from the config and be wrapped in a circuit breaker**
