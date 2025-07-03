package com.example.gateway.service;

import com.example.gateway.adapter.keyvault.client.AzureKeyVaultClient;
import com.example.gateway.domain.entity.TokenInfo;
import com.example.gateway.exception.TokenException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Token Manager - Simple Redis-based token storage
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenManagerService {

  @Qualifier("pingIdentityHttpClient")

  private final OkHttpClient pingHttpClient;

  @Qualifier("entraHttpClient")
  private final OkHttpClient entraHttpClient;

  @Qualifier("managedIdentityHttpClient")
  private final OkHttpClient managedIdentityHttpClient;

  private final ObjectMapper objectMapper;
  private final AzureKeyVaultClient keyVaultClient;
  private final RedisTemplate<String, String> redisTemplate;
  private final DistributedLockService lockService;

  @Value("${app.auth.ping.client-id}")
  private String pingClientId;

  @Value("${app.auth.ping.token-uri}")
  private String pingTokenUri;

  @Value("${app.auth.entra.tenant-id}")
  private String entraTenantId;

  @Value("${app.auth.entra.client-id}")
  private String entraClientId;

  @Value("${app.auth.entra.scope}")
  private String entraScope;

  private static final String TOKEN_PREFIX = "token:";
  private static final Duration REFRESH_THRESHOLD = Duration.ofMinutes(5);

  public static final String TOKEN_TYPE_PING = "PING_IDENTITY";
  public static final String TOKEN_TYPE_ENTRA = "MICROSOFT_ENTRA";
  public static final String TOKEN_TYPE_MANAGED_IDENTITY = "MANAGED_IDENTITY";

  /**
   * Get access token
   */
  public String getAccessToken(String tokenType) {
    String redisKey = TOKEN_PREFIX + tokenType;
    String tokenJson = redisTemplate.opsForValue().get(redisKey);

    if (tokenJson != null) {
      try {
        TokenInfo tokenInfo = objectMapper.readValue(tokenJson, TokenInfo.class);
        if (!tokenInfo.isExpired() && !tokenInfo.expiresWithin(REFRESH_THRESHOLD)) {
          return tokenInfo.accessToken();
        }
      } catch (Exception e) {
        log.error("Failed to parse token from Redis", e);
      }
    }

    // Token missing or needs refresh
    return refreshTokenWithLock(tokenType);
  }

  /**
   * Refresh token with distributed lock
   */
  private String refreshTokenWithLock(String tokenType) {
    String lockKey = "token:lock:" + tokenType;
    String lockToken = lockService.tryAcquireLock(lockKey, Duration.ofSeconds(10));

    if (lockToken == null) {
      // Wait and retry once
      try {
        Thread.sleep(500);
        String tokenJson = redisTemplate.opsForValue().get(TOKEN_PREFIX + tokenType);
        if (tokenJson != null) {
          TokenInfo tokenInfo = objectMapper.readValue(tokenJson, TokenInfo.class);
          if (!tokenInfo.isExpired()) {
            return tokenInfo.accessToken();
          }
        }
      } catch (Exception e) {
        log.error("Error waiting for token refresh", e);
      }
      throw new TokenException("Failed to acquire token");
    }

    try {
      // Double-check after lock
      String tokenJson = redisTemplate.opsForValue().get(TOKEN_PREFIX + tokenType);
      if (tokenJson != null) {
        TokenInfo tokenInfo = objectMapper.readValue(tokenJson, TokenInfo.class);
        if (!tokenInfo.isExpired()) {
          return tokenInfo.accessToken();
        }
      }

      // Refresh token
      TokenInfo newToken = switch (tokenType) {
        case TOKEN_TYPE_PING -> acquirePingIdentityToken();
        case TOKEN_TYPE_ENTRA -> acquireEntraToken();
        case TOKEN_TYPE_MANAGED_IDENTITY -> acquireManagedIdentityToken();
        default -> throw new TokenException("Unknown token type: " + tokenType);
      };

      // Store in Redis
      String newTokenJson = objectMapper.writeValueAsString(newToken);
      redisTemplate.opsForValue().set(
          TOKEN_PREFIX + tokenType,
          newTokenJson,
          newToken.remainingLifetime()
                                     );

      return newToken.accessToken();

    } catch (Exception e) {
      log.error("Failed to refresh token", e);
      throw new TokenException("Token refresh failed", e);
    } finally {
      lockService.releaseLock(lockKey, lockToken);
    }
  }

  private TokenInfo acquirePingIdentityToken() throws IOException {
    String clientSecret = keyVaultClient.getSecret("ping-api-client-secret");

    FormBody formBody = new FormBody.Builder()
        .add("grant_type", "client_credentials")
        .add("scope", "api:read api:write")
        .build();

    Request request = new Request.Builder()
        .url(pingTokenUri)
        .post(formBody)
        .header("Authorization", Credentials.basic(pingClientId, clientSecret))
        .build();

    try (Response response = pingHttpClient.newCall(request).execute()) {
      if (!response.isSuccessful()) {
        throw new TokenException("Ping token request failed: " + response.code());
      }

      Map<String, Object> tokenResponse = objectMapper.readValue(
          response.body().string(), Map.class);

      String accessToken = (String) tokenResponse.get("access_token");
      Integer expiresIn = (Integer) tokenResponse.get("expires_in");

      return new TokenInfo(
          TOKEN_TYPE_PING,
          accessToken,
          Instant.now().plusSeconds(expiresIn != null ? expiresIn : 3600)
      );
    }
  }

  private TokenInfo acquireEntraToken() throws IOException {
    String clientSecret = keyVaultClient.getSecret("entra-client-secret");

    FormBody formBody = new FormBody.Builder()
        .add("grant_type", "client_credentials")
        .add("client_id", entraClientId)
        .add("client_secret", clientSecret)
        .add("scope", entraScope)
        .build();

    Request request = new Request.Builder()
        .url(String.format("https://login.microsoftonline.com/%s/oauth2/v2.0/token", entraTenantId))
        .post(formBody)
        .build();

    try (Response response = entraHttpClient.newCall(request).execute()) {
      if (!response.isSuccessful()) {
        throw new TokenException("Entra token request failed: " + response.code());
      }

      Map<String, Object> tokenResponse = objectMapper.readValue(
          response.body().string(), Map.class);

      String accessToken = (String) tokenResponse.get("access_token");
      Integer expiresIn = (Integer) tokenResponse.get("expires_in");

      return new TokenInfo(
          TOKEN_TYPE_ENTRA,
          accessToken,
          Instant.now().plusSeconds(expiresIn != null ? expiresIn : 3600)
      );
    }
  }

  private TokenInfo acquireManagedIdentityToken() throws IOException {
    String identityEndpoint = System.getenv("IDENTITY_ENDPOINT");
    String identityHeader = System.getenv("IDENTITY_HEADER");

    Request request = new Request.Builder()
        .url(identityEndpoint + "?resource=https://vault.azure.net&api-version=2019-08-01")
        .header("X-IDENTITY-HEADER", identityHeader)
        .get()
        .build();

    try (Response response = managedIdentityHttpClient.newCall(request).execute()) {
      if (!response.isSuccessful()) {
        throw new TokenException("Managed Identity token request failed: " + response.code());
      }

      Map<String, Object> tokenResponse = objectMapper.readValue(
          response.body().string(), Map.class);

      String accessToken = (String) tokenResponse.get("access_token");
      String expiresOn = (String) tokenResponse.get("expires_on");

      return new TokenInfo(
          TOKEN_TYPE_MANAGED_IDENTITY,
          accessToken,
          Instant.ofEpochSecond(Long.parseLong(expiresOn))
      );
    }
  }
}
