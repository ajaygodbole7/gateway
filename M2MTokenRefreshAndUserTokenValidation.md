
### 1. Where is the M2M token stored?

The M2M token is stored in **Redis as a simple String value**.

Let's break down the exact lines of code in `M2MTokenManagerService.java` that handle this:

**In the `performRefresh` method:**

1.  **Acquisition:** The service calls `acquireNewM2MToken(...)` which returns a new `M2MToken` record.
    ```java
    M2MToken newToken = acquireNewM2MToken(provider);
    ```
2.  **Serialization:** This `M2MToken` record is then serialized into a JSON string using Jackson `ObjectMapper`.
    ```java
    String newTokenJson = objectMapper.writeValueAsString(newToken);
    ```
    This `newTokenJson` string might look something like this:
    `{"tokenProvider":"PING_IDENTITY","accessToken":"eyJhbG...","expiresAt":"2023-11-01T12:00:00Z"}`

3.  **The Redis Call (The `SET` command):** The JSON string is then stored in Redis using a `SET` command with a Time-To-Live (TTL).
    ```java
    // The key is dynamically created, e.g., "m2m_token:PING_IDENTITY"
    String redisKey = TOKEN_PREFIX + provider.name(); 

    // Calculate a safe TTL
    long ttlSeconds = Math.max(60, newToken.remainingLifetime().toSeconds());

    // This is the Redis SET command with expiration
    redisTemplate.opsForValue().set(redisKey, newTokenJson, ttlSeconds, TimeUnit.SECONDS);
    ```
    This single line of code is the entire storage mechanism. It executes a `SET m2m_token:PING_IDENTITY "{\"json\":\"...\"}" EX 3540` command in Redis.

### 2. How do the user token validation services use it?

The user token validation services (`PingTokenValidationService` and `EntraTokenValidationService`) are **consumers** of the `M2MTokenManagerService`. They do not know or care about Redis or how the M2M token is stored. They simply ask the manager service for a valid token when they need one.

Let's trace the flow in `PingTokenValidationService.java`:

1.  **Request for M2M Token:** Inside the `validateAndRefresh` method, the very first thing it does is call the `M2MTokenManagerService` to get the Bearer token it needs to authenticate itself to Ping.
    ```java
    // From PingTokenValidationService.java
    public Optional<String> validateAndRefresh(String userPlaintextToken) {
        log.debug("Requesting M2M token to validate a user token from Ping Identity.");
        
        // This is the crucial call. It blocks and waits until a valid token is returned.
        String gatewayM2MToken = m2mTokenManagerService.getAccessToken(IdpProvider.PING_IDENTITY);
    
        // ... rest of the method uses gatewayM2MToken ...
    }
    ```

2.  **M2MTokenManagerService Logic:** When `getAccessToken` is called, it performs its full logic:
    *   It constructs the Redis key: `m2m_token:PING_IDENTITY`.
    *   It makes a `GET` call to Redis to check the cache.
    *   If the token is fresh, it's returned immediately.
    *   If the token is stale, it starts the distributed lock and refresh process.
    *   Crucially, from the perspective of `PingTokenValidationService`, **this call is synchronous and blocking**. It will not proceed until `getAccessToken` has successfully returned a valid token string.

3.  **Using the M2M Token:** Once `gatewayM2MToken` has a value, `PingTokenValidationService` uses it to build the `Authorization` header for its call to the Ping validation endpoint.
    ```java
    // From PingTokenValidationService.java
    Request request = new Request.Builder()
            .url(validationUri)
            // The M2M token is used here to authenticate the gateway.
            .header("Authorization", "Bearer " + gatewayM2MToken) 
            // The user's token is sent in the body for validation.
            .post(formBody)
            .build();
    ```

### Summary of the Data Flow

Here is the end-to-end flow, clarifying the Redis calls:

1.  A user API request hits the `SessionAuthenticationFilter`.
2.  The filter calls `PingTokenValidationService.validateAndRefresh(userToken)`.
3.  `PingTokenValidationService` calls `M2MTokenManagerService.getAccessToken(PING)`.
4.  `M2MTokenManagerService` makes a **`GET m2m_token:PING_IDENTITY`** call to Redis.
5.  **Scenario A (Cache Hit):** The token in Redis is fresh. The JSON is deserialized, the `accessToken` string is returned to `PingTokenValidationService`.
6.  **Scenario B (Cache Miss):**
    *   The token is stale/missing.
    *   `M2MTokenManagerService` makes a **`SET lock:m2m_token:PING_IDENTITY ... NX EX ...`** call to Redis to acquire a distributed lock.
    *   The leader instance makes an HTTP call to Ping to get a new token.
    *   The leader instance makes a **`SET m2m_token:PING_IDENTITY "..." EX ...`** call to Redis to store the new token.
    *   The leader instance makes a **`DEL lock:m2m_token:PING_IDENTITY`** call to release the lock.
    *   The access token string is returned to `PingTokenValidationService`.
7.  `PingTokenValidationService` now has the `gatewayM2MToken` and proceeds to make its HTTP call to the user token validation endpoint.

This architecture ensures a clean separation of concerns: the `M2MTokenManagerService` is the expert on caching and refreshing the gateway's own credentials, while the validation services are simply consumers of those credentials.
