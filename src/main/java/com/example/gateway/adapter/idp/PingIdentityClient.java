package com.example.gateway.adapter.idp;

import com.example.gateway.adapter.keyvault.client.AzureKeyVaultClient;
import com.example.gateway.domain.entity.UserPrincipal;
import com.example.gateway.exception.OAuth2Exception;
import com.example.gateway.properties.ApplicationProperties;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class PingIdentityClient implements IdpClient {

  private static final String CLIENT_SECRET_NAME = "ping-client-secret";

  private final ApplicationProperties properties;
  private final AzureKeyVaultClient keyVaultClient;
  private final OkHttpClient defaultOkHttpClient;
  private final ObjectMapper objectMapper;

  @Override
  public String getAuthorizationEndpoint() {
    return properties.auth().ping().authorizationUri();
  }

  @Override
  public String getClientId() {
    return properties.auth().ping().clientId();
  }

  @Override
  @CircuitBreaker(name = "pingIdentity", fallbackMethod = "exchangeCodeFallback")
  public TokenResponse exchangeCodeForTokens(String code, String codeVerifier, String redirectUri) {
    log.debug("Exchanging authorization code for tokens with Ping Identity");

    String clientSecret = keyVaultClient.getSecret(CLIENT_SECRET_NAME);
    String credentials = Credentials.basic(getClientId(), clientSecret);

    FormBody formBody = new FormBody.Builder()
        .add("grant_type", "authorization_code")
        .add("code", code)
        .add("redirect_uri", redirectUri)
        .add("code_verifier", codeVerifier)
        .build();

    Request request = new Request.Builder()
        .url(properties.auth().ping().tokenUri())
        .header("Authorization", credentials)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .post(formBody)
        .build();

    try (Response response = httpClient.newCall(request).execute()) {
      if (!response.isSuccessful() || response.body() == null) {
        throw new OAuth2Exception("Token exchange failed with Ping Identity, status: " + response.code());
      }

      Map<String, Object> tokenResponse = objectMapper.readValue(
          response.body().string(),
          new TypeReference<>() {}
                                                                );

      return new TokenResponse(
          (String) tokenResponse.get("id_token"),
          (String) tokenResponse.get("access_token"),
          (String) tokenResponse.get("refresh_token"),
          ((Number) tokenResponse.get("expires_in")).longValue()
      );

    } catch (IOException e) {
      throw new OAuth2Exception("Token exchange failed due to network error", e);
    }
  }

  public TokenResponse exchangeCodeFallback(String code, String codeVerifier,
                                            String redirectUri, Throwable ex) {
    log.error("Ping Identity circuit breaker is open during token exchange.", ex);
    throw new OAuth2Exception("Ping Identity is temporarily unavailable.", ex);
  }

  @Override
  public UserPrincipal extractUserPrincipal(Jwt jwt) {
    return new UserPrincipal(
        jwt.getSubject(),
        jwt.getClaimAsString("preferred_username"),
        jwt.getClaimAsString("email"),
        jwt.getClaimAsString("given_name"),
        jwt.getClaimAsString("family_name"),
        System.currentTimeMillis(),
        (long) properties.security().session().slidingWindowMinutes() * 60
    );
  }
}
