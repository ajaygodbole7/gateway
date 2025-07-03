package com.example.gateway.adapter.keyvault.client;


import com.example.gateway.adapter.keyvault.dto.SecretResponse;
import com.example.gateway.exception.KeyVaultException;
import com.example.gateway.security.ManagedIdentityTokenProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.Response;
import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Azure Key Vault Client using Managed Identity
 * <p>
 * Features: - Managed Identity authentication (no secrets) - Secret caching with TTL - Circuit
 * breaker pattern - Optimized HTTP client usage
 */
@Slf4j
@Component
public class AzureKeyVaultClient {

  private static final Duration CACHE_TTL = Duration.ofMinutes(5);
  private static final long CIRCUIT_RESET_TIMEOUT = 30000;
  private final OkHttpClient httpClient;
  private final ObjectMapper objectMapper;
  private final ManagedIdentityTokenProvider tokenProvider;
  private final String keyVaultUrl;
  private final String apiVersion = "7.4";
  private final ConcurrentHashMap<String, CachedSecret> secretCache = new ConcurrentHashMap<>();
  private volatile boolean circuitOpen = false;
  private volatile long circuitOpenTime = 0;

  public AzureKeyVaultClient(
      @Value("${azure.keyvault.uri}") String keyVaultUrl,
      @Qualifier("fastOkHttpClient") OkHttpClient httpClient,
      ObjectMapper objectMapper,
      ManagedIdentityTokenProvider tokenProvider) {
    this.keyVaultUrl = keyVaultUrl;
    this.httpClient = httpClient;
    this.objectMapper = objectMapper;
    this.tokenProvider = tokenProvider;
  }

  /**
   * Get secret with caching and circuit breaker
   */
  public String getSecret(String secretName) {
    CachedSecret cached = secretCache.get(secretName);
    if (cached != null && !cached.isExpired()) {
      log.debug("Returning cached secret: {}",
                secretName);
      return cached.value;
    }

    if (isCircuitOpen()) {
      throw new KeyVaultException("Key Vault circuit breaker is open");
    }

    try {
      String secretValue = fetchSecretFromKeyVault(secretName);
      secretCache.put(secretName,
                      new CachedSecret(secretValue));
      circuitOpen = false;
      return secretValue;

    } catch (Exception e) {
      handleKeyVaultError(e);
      throw new KeyVaultException("Failed to retrieve secret",
                                  e);
    }
  }

  private String fetchSecretFromKeyVault(String secretName) throws IOException {
    String url = String.format("%s/secrets/%s?api-version=%s",
                               keyVaultUrl,
                               secretName,
                               apiVersion);

    Request request = new Request.Builder()
        .url(url)
        .header("Authorization",
                "Bearer " + tokenProvider.getAccessToken())
        .get()
        .build();

    try (Response response = httpClient.newCall(request).execute()) {
      if (!response.isSuccessful()) {
        throw new KeyVaultException("Key Vault error: " + response.code());
      }

      ResponseBody body = response.body();
      if (body == null) {
        throw new KeyVaultException("Empty response from Key Vault");
      }

      SecretResponse secretResponse = objectMapper.readValue(
          body.string(),
          SecretResponse.class);

      return secretResponse.value();
    }
  }

  private boolean isCircuitOpen() {
    if (!circuitOpen) {
      return false;
    }

    if (System.currentTimeMillis() - circuitOpenTime > CIRCUIT_RESET_TIMEOUT) {
      circuitOpen = false;
      log.info("Circuit breaker reset");
      return false;
    }

    return true;
  }

  private void handleKeyVaultError(Exception e) {
    log.error("Key Vault error occurred",
              e);
    circuitOpen = true;
    circuitOpenTime = System.currentTimeMillis();
    log.warn("Circuit breaker opened due to Key Vault failure");
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
