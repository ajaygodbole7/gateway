package com.example.gateway.adapter.keyvault.client;

import com.example.gateway.adapter.keyvault.dto.SecretResponse;
import com.example.gateway.exception.KeyVaultException;
import com.example.gateway.security.ManagedIdentityTokenProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A resilient and cached client for interacting with Azure Key Vault.
 * This class is responsible for securely fetching secrets and is protected by a circuit breaker.
 */
@Slf4j
@Component
public class AzureKeyVaultClient {

  private static final String KEY_VAULT_BREAKER = "keyVault";
  private static final Duration CACHE_TTL = Duration.ofMinutes(5);
  private static final String API_VERSION = "7.4";

  private final OkHttpClient httpClient;
  private final ObjectMapper objectMapper;
  private final ManagedIdentityTokenProvider tokenProvider;
  private final String keyVaultUrl;
  private final ConcurrentHashMap<String, CachedSecret> secretCache = new ConcurrentHashMap<>();

  public AzureKeyVaultClient(
      @Value("${azure.keyvault.uri}") String keyVaultUrl,
      @Qualifier("fastOkHttpClient") OkHttpClient httpClient,
      ObjectMapper objectMapper,
      ManagedIdentityTokenProvider tokenProvider) {
    this.keyVaultUrl = keyVaultUrl;
    this.httpClient = httpClient;
    this.objectMapper = objectMapper;
    this.tokenProvider = tokenProvider;
    log.info("Initialized Azure Key Vault client for: {}", keyVaultUrl);
  }

  /**
   * Retrieves a secret from Key Vault, utilizing a cache and a circuit breaker.
   * The method first checks a local, in-memory cache. On a miss, it calls Key Vault.
   * The call is protected by the "keyVault" circuit breaker.
   *
   * @param secretName The name of the secret to retrieve.
   * @return The secret value as a String.
   * @throws KeyVaultException if the secret cannot be retrieved and no stale cache is available.
   */
  @CircuitBreaker(name = KEY_VAULT_BREAKER, fallbackMethod = "getSecretFallback")
  public String getSecret(String secretName) {
    CachedSecret cached = secretCache.get(secretName);
    if (cached != null && !cached.isExpired()) {
      log.debug("Returning fresh cached secret: {}", secretName);
      return cached.value;
    }

    try {
      log.info("Cache miss or stale. Fetching secret from Key Vault: {}", secretName);
      String secretValue = fetchSecretFromKeyVault(secretName);
      secretCache.put(secretName, new CachedSecret(secretValue));
      log.info("Secret cached successfully: {}", secretName);
      return secretValue;
    } catch (IOException e) {
      // Let the circuit breaker handle this exception.
      throw new KeyVaultException("Failed to retrieve secret from Key Vault: " + secretName, e);
    }
  }

  /**
   * Fallback method for the getSecret circuit breaker.
   * This method is invoked when the circuit is open. It attempts to return a stale
   * value from the cache to maintain partial functionality. If no stale value is
   * available, it fails hard by re-throwing a specific exception.
   *
   * @param secretName The name of the secret that was requested.
   * @param ex         The exception that caused the circuit to open.
   * @return A stale secret value if available.
   * @throws KeyVaultException if no cached value is available.
   */
  public String getSecretFallback(String secretName, Throwable ex) {
    log.warn("Key Vault circuit breaker is OPEN for secret: {}. Attempting to use stale cache.", secretName);
    CachedSecret staleCache = secretCache.get(secretName);
    if (staleCache != null) {
      log.warn("Resilience: Returning STALE cached value for secret: {}", secretName);
      return staleCache.value;
    }
    log.error("No cached value available for secret: {}. The operation cannot proceed.", secretName);
    throw new KeyVaultException("Key Vault is unavailable and no cached value is available for: " + secretName, ex);
  }

  private String fetchSecretFromKeyVault(String secretName) throws IOException {
    String url = String.format("%s/secrets/%s?api-version=%s", keyVaultUrl, secretName, API_VERSION);
    Request request = new Request.Builder()
        .url(url)
        .header("Authorization", "Bearer " + tokenProvider.getAccessToken())
        .get()
        .build();

    try (Response response = httpClient.newCall(request).execute()) {
      if (!response.isSuccessful()) {
        throw new KeyVaultException("Key Vault returned a non-successful status: " + response.code());
      }

      ResponseBody body = response.body();
      if (body == null) {
        throw new KeyVaultException("Received an empty response body from Key Vault");
      }

      SecretResponse secretResponse = objectMapper.readValue(body.string(), SecretResponse.class);
      return secretResponse.value();
    }
  }

  private static class CachedSecret {
    final String value;
    final long expiryTime;

    CachedSecret(String value) {
      this.value = value;
      this.expiryTime = System.currentTimeMillis() + CACHE_TTL.toMillis();
    }

    boolean isExpired() {
      return System.currentTimeMillis() > expiryTime;
    }
  }
}
