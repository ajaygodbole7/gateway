package com.example.gateway.service;

import com.example.gateway.adapter.keyvault.client.AzureKeyVaultClient;
import com.example.gateway.domain.entity.IdpProvider;
import com.example.gateway.domain.entity.M2MToken;
import com.example.gateway.exception.EntraException;
import com.example.gateway.exception.TokenException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.ClientCredentialParameters;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.MalformedURLException;
import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Manages the lifecycle of M2M tokens, including a proactive background refresh
 * mechanism and graceful shutdown procedures. It uses embedded constants for all keys
 * to improve maintainability and prevent errors.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class M2MTokenManagerService {

  // --- Embedded Constants ---
  private static final String M2M_TOKEN_REDIS_PREFIX = "m2m_token:";
  private static final String DISTRIBUTED_LOCK_PREFIX = "lock:m2m_token:";
  private static final Duration LOCK_TTL = Duration.ofSeconds(20);
  private static final Duration REFRESH_THRESHOLD = Duration.ofMinutes(5);
  private static final int REFRESH_RETRY_ATTEMPTS = 15;
  private static final long REFRESH_RETRY_WAIT_MS = 300;

  // --- Injected Dependencies ---
  @Qualifier("defaultOkHttpClient")
  private final OkHttpClient defaultHttpClient;
  private final ObjectMapper objectMapper;
  private final AzureKeyVaultClient keyVaultClient;
  private final RedisTemplate<String, String> redisTemplate;
  private final DistributedLockService lockService;

  // --- Configuration Properties ---
  @Value("${app.auth.ping.client-id}")
  private String pingClientId;
  @Value("${app.auth.ping.token-uri}")
  private String pingTokenUri;
  @Value("${app.auth.entra.authority}")
  private String entraAuthority;
  @Value("${app.auth.entra.client-id}")
  private String entraClientId;
  @Value("${app.auth.entra.gateway-m2m-audience}")
  private String entraM2mAudience;

  // --- Internal State ---
  private ConfidentialClientApplication msalClient;
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

  public void initialize() {
    log.info("Initializing M2M Token Manager Service...");
    try {
      String entraClientSecret = keyVaultClient.getSecret("entra-client-secret");
      this.msalClient = ConfidentialClientApplication.builder(
              entraClientId,
              ClientCredentialFactory.createFromSecret(entraClientSecret))
          .authority(entraAuthority)
          .build();
      scheduler.scheduleWithFixedDelay(this::proactiveRefreshAllTokens, 1, 1, TimeUnit.MINUTES);
    } catch (MalformedURLException e) {
      throw new EntraException("Failed to initialize MSAL client - invalid authority URL", e);
    }
  }

  public void shutdown() {
    log.info("Shutting down M2M Token Manager's background refresh scheduler...");
    scheduler.shutdownNow();
    try {
      if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
        log.error("Scheduler did not terminate in 5 seconds.");
      }
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
    }
  }

  public String getAccessToken(IdpProvider provider) {
    M2MToken cachedToken = getFreshTokenFromCache(provider);
    if (cachedToken != null) {
      return cachedToken.accessToken();
    }
    return refreshTokenWithLock(provider);
  }

  private String refreshTokenWithLock(IdpProvider provider) {
    String redisKey = M2M_TOKEN_REDIS_PREFIX + provider.name();
    String lockKey = DISTRIBUTED_LOCK_PREFIX + provider.name();
    String lockToken = lockService.tryAcquireLock(lockKey, LOCK_TTL);

    if (lockToken == null) {
      return waitForLeaderAndRetry(provider);
    }

    try {
      M2MToken token = getFreshTokenFromCache(provider);
      if (token != null) {
        return token.accessToken();
      }
      return performRefresh(provider, redisKey);
    } finally {
      lockService.releaseLock(lockKey, lockToken);
    }
  }

  private M2MToken getFreshTokenFromCache(IdpProvider provider) {
    String redisKey = M2M_TOKEN_REDIS_PREFIX + provider.name();
    String tokenJson = redisTemplate.opsForValue().get(redisKey);
    if (tokenJson == null) return null;
    try {
      M2MToken token = objectMapper.readValue(tokenJson, M2MToken.class);
      if (!token.expiresWithin(REFRESH_THRESHOLD)) {
        return token;
      }
    } catch (Exception e) {
      log.error("Could not parse M2M token from Redis for {}.", provider, e);
    }
    return null;
  }

  private String performRefresh(IdpProvider provider, String redisKey) {
    log.info("This instance is the leader for {} M2M token refresh.", provider);
    try {
      M2MToken newToken = acquireNewM2MToken(provider);
      String newTokenJson = objectMapper.writeValueAsString(newToken);
      long ttlSeconds = Math.max(60, newToken.remainingLifetime().toSeconds());
      redisTemplate.opsForValue().set(redisKey, newTokenJson, ttlSeconds, TimeUnit.SECONDS);
      return newToken.accessToken();
    } catch (Exception e) {
      throw new TokenException("M2M token refresh failed for leader thread", e);
    }
  }

  private String waitForLeaderAndRetry(IdpProvider provider) {
    log.warn("Another instance holds the refresh lock for {}. Entering wait-and-retry loop.", provider);
    for (int i = 0; i < REFRESH_RETRY_ATTEMPTS; i++) {
      try {
        Thread.sleep(REFRESH_RETRY_WAIT_MS);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new TokenException("Interrupted while waiting for token refresh lock.", e);
      }
      M2MToken token = getFreshTokenFromCache(provider);
      if (token != null) {
        log.info("Follower instance successfully retrieved token from cache for {} on attempt #{}", provider, i + 1);
        return token.accessToken();
      }
    }
    throw new TokenException("Timed out waiting for another instance to refresh the M2M token for " + provider);
  }

  private void proactiveRefreshAllTokens() {
    log.debug("Running proactive M2M token refresh check...");
    for (IdpProvider provider : IdpProvider.values()) {
      try {
        if (getFreshTokenFromCache(provider) == null) {
          log.info("Proactively refreshing M2M token for {} as it is missing or expiring soon.", provider);
          refreshTokenWithLock(provider);
        }
      } catch (Exception e) {
        log.error("Proactive refresh for provider {} failed.", provider, e);
      }
    }
  }

  private M2MToken acquireNewM2MToken(IdpProvider provider) throws IOException {
    return switch (provider) {
      case PING_IDENTITY -> acquirePingIdentityM2MToken();
      case MICROSOFT_ENTRA -> acquireEntraM2MToken();
    };
  }

  @CircuitBreaker(name = "pingIdentity", fallbackMethod = "pingTokenAcquisitionFallback")
  private M2MToken acquirePingIdentityM2MToken() throws IOException {
    String clientSecret = keyVaultClient.getSecret("ping-client-secret");
    FormBody formBody = new FormBody.Builder().add("grant_type", "client_credentials").build();
    Request request = new Request.Builder().url(pingTokenUri).post(formBody)
        .header("Authorization", Credentials.basic(pingClientId, clientSecret)).build();
    try (Response response = defaultHttpClient.newCall(request).execute()) {
      if (!response.isSuccessful() || response.body() == null) {
        throw new TokenException("Ping M2M token request failed: " + response.code());
      }
      Map<String, Object> tokenResponse = objectMapper.readValue(response.body().string(), Map.class);
      return M2MToken.withExpiresIn(IdpProvider.PING_IDENTITY, (String) tokenResponse.get("access_token"), ((Number) tokenResponse.get("expires_in")).longValue());
    }
  }

  @CircuitBreaker(name = "microsoftEntra", fallbackMethod = "entraTokenAcquisitionFallback")
  private M2MToken acquireEntraM2MToken() {
    try {
      ClientCredentialParameters parameters = ClientCredentialParameters.builder(
          Collections.singleton(entraM2mAudience)).build();
      IAuthenticationResult result = msalClient.acquireToken(parameters).join();
      long expiresIn = Duration.between(java.time.Instant.now(), result.expiresOnDate().toInstant()).getSeconds();
      return M2MToken.withExpiresIn(IdpProvider.MICROSOFT_ENTRA, result.accessToken(), Math.max(0, expiresIn));
    } catch (Exception e) {
      throw new EntraException("Failed to acquire M2M access token from Entra", e);
    }
  }

  private M2MToken pingTokenAcquisitionFallback(Throwable ex) {
    throw new TokenException("Ping Identity service is temporarily unavailable for M2M tokens.", ex);
  }

  private M2MToken entraTokenAcquisitionFallback(Throwable ex) {
    throw new EntraException("Microsoft Entra service is temporarily unavailable for M2M tokens.", ex);
  }
}
