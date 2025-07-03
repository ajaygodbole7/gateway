package com.example.gateway.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

/**
 * Azure Managed Identity Token Provider
 *
 * Obtains access tokens for Key Vault using Managed Identity
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ManagedIdentityTokenProvider {

  private static final String IDENTITY_ENDPOINT = System.getenv("IDENTITY_ENDPOINT");
  private static final String IDENTITY_HEADER = System.getenv("IDENTITY_HEADER");
  private static final String RESOURCE = "https://vault.azure.net";

  @Qualifier("fastOkHttpClient")
  private final OkHttpClient httpClient;
  private final ObjectMapper objectMapper;

  private volatile String cachedToken;
  private volatile long tokenExpiry;

  /**
   * Get access token with caching
   */
  public synchronized String getAccessToken() {
    if (cachedToken != null && System.currentTimeMillis() < tokenExpiry - 60000) {
      return cachedToken;
    }

    try {
      return fetchNewToken();
    } catch (Exception e) {
      log.error("Failed to get managed identity token", e);
      throw new RuntimeException("Failed to authenticate with managed identity", e);
    }
  }

  private String fetchNewToken() throws IOException {
    String url = IDENTITY_ENDPOINT + "?resource=" + RESOURCE + "&api-version=2019-08-01";

    Request request = new Request.Builder()
        .url(url)
        .header("X-IDENTITY-HEADER", IDENTITY_HEADER)
        .get()
        .build();

    try (Response response = httpClient.newCall(request).execute()) {
      if (!response.isSuccessful()) {
        throw new IOException("Failed to get token: " + response.code());
      }

      String responseBody = response.body().string();
      Map<String, Object> tokenResponse = objectMapper.readValue(responseBody, Map.class);

      cachedToken = (String) tokenResponse.get("access_token");
      String expiresOn = (String) tokenResponse.get("expires_on");
      tokenExpiry = Long.parseLong(expiresOn) * 1000;

      return cachedToken;
    }
  }
}
