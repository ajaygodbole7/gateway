package com.example.gateway.service;

import com.example.gateway.adapter.keyvault.client.AzureKeyVaultClient;
import com.example.gateway.properties.ApplicationProperties;
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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.MalformedURLException;
import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class M2MTokenManagerService implements InitializingBean {

  private static final String M2M_TOKEN_REDIS_PREFIX = "m2m_token:";
  private static final String DISTRIBUTED_LOCK_PREFIX = "lock:m2m_token:";
  private static final Duration LOCK_TTL = Duration.ofSeconds(20);
  private static final Duration REFRESH_THRESHOLD = Duration.ofMinutes(5);

  @Qualifier("defaultOkHttpClient")
  private final OkHttpClient defaultHttpClient;
  private final ObjectMapper objectMapper;
  private final AzureKeyVaultClient keyVaultClient;
  private final RedisTemplate<String, String> redisTemplate;
  private final DistributedLockService lockService;
  private final ApplicationProperties properties; // The single, top-level properties bean

  private ConfidentialClientApplication msalClient;

  @Override
  public void afterPropertiesSet() throws Exception {
    log.info("Initializing M2M Token Manager Service and MSAL client...");
    try {
      String entraClientSecret = keyVaultClient.getSecret("entra-client-secret");
      this.msalClient = ConfidentialClientApplication.builder(
              properties.auth().entra().clientId(),
              ClientCredentialFactory.createFromSecret(entraClientSecret))
          .authority(properties.auth().entra().authority())
          .build();
    } catch (MalformedURLException e) {
      throw new EntraException("Failed to initialize MSAL client - invalid authority URL", e);
    }
  }

  @Scheduled(
      fixedRateString = "${app.m2m.refresh.rate}",
      initialDelayString = "${app.m2m.refresh.initial-delay}"
  )
  public void proactiveRefreshAllTokens() {
    if (!properties.m2m().refresh().enabled()) {
      log.trace("Proactive M2M token refresh is disabled.");
      return;
    }

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

  public String getAccessToken(IdpProvider provider) {
    M2MToken cachedToken = getFreshTokenFromCache(provider);
    if (cachedToken != null) {
      return cachedToken.accessToken();
    }
    return refreshTokenWithLock(provider);
  }

  private String refreshTokenWithLock(IdpProvider provider) {
    String lockKey = DISTRIBUTED_LOCK_PREFIX + provider.name();
    String lockToken = lockService.tryAcquireLock(lockKey, LOCK_TTL);
    if (lockToken == null) {
      return waitForLeaderAndRetry(provider);
    }
    try {
      M2MToken token = getFreshTokenFromCache(provider);
      if (token != null) { return token.accessToken(); }
      return performRefresh(provider);
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

  private String performRefresh(IdpProvider provider) {
    String redisKey = M2M_TOKEN_REDIS_PREFIX + provider.name();
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

  @Retryable(
      value = { TokenException.class },
      maxAttemptsExpression = "${app.m2m.retry.max-attempts}",
      backoff = @Backoff(delayExpression = "${app.m2m.retry.delay-ms}")
  )
  private String waitForLeaderAndRetry(IdpProvider provider) {
    log.warn("Another instance holds the refresh lock for {}. Waiting and retrying from cache...", provider);
    M2MToken token = getFreshTokenFromCache(provider);
    if (token != null) { return token.accessToken(); }
    throw new TokenException("Token for " + provider + " not yet available in cache.");
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
    Request request = new Request.Builder().url(properties.auth().ping().tokenUri()).post(formBody)
        .header("Authorization", Credentials.basic(properties.auth().ping().clientId(), clientSecret)).build();
    try (Response response = defaultHttpClient.newCall(request).execute()) {
      if (!response.isSuccessful() || response.body() == null) { throw new TokenException("Ping M2M token request failed: " + response.code()); }
      Map<String, Object> tokenResponse = objectMapper.readValue(response.body().string(), Map.class);
      return M2MToken.withExpiresIn(IdpProvider.PING_IDENTITY, (String) tokenResponse.get("access_token"), ((Number) tokenResponse.get("expires_in")).longValue());
    }
  }

  @CircuitBreaker(name = "microsoftEntra", fallbackMethod = "entraTokenAcquisitionFallback")
  private M2MToken acquireEntraM2MToken() {
    try {
      ClientCredentialParameters parameters = ClientCredentialParameters.builder(
          Collections.singleton(properties.auth().entra().gatewayM2mAudience())).build();
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
