package com.example.gateway.adapter.idp;

import com.example.gateway.adapter.keyvault.client.AzureKeyVaultClient;
import com.example.gateway.domain.entity.UserPrincipal;
import com.example.gateway.exception.OAuth2Exception;
import com.example.gateway.properties.ApplicationProperties;
import com.microsoft.aad.msal4j.*;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;


import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.concurrent.CompletionException;

@Component
@RequiredArgsConstructor
@Slf4j
public class MicrosoftEntraClient implements IdpClient {

  private static final String CLIENT_SECRET_NAME = "entra-client-secret";

  private final ApplicationProperties properties;
  private final AzureKeyVaultClient keyVaultClient;
  private ConfidentialClientApplication msalClient;

  @PostConstruct
  public void init() throws Exception {
    String clientSecret = keyVaultClient.getSecret(CLIENT_SECRET_NAME);
    this.msalClient = ConfidentialClientApplication.builder(
            properties.auth().entra().clientId(),
            ClientCredentialFactory.createFromSecret(clientSecret))
        .authority(properties.auth().entra().authority())
        .build();

    log.info("Microsoft Entra client initialized");
  }

  @Override
  public String getAuthorizationEndpoint() {
    return msalClient.getAuthorizationEndpoint();
  }

  @Override
  public String getClientId() {
    return properties.auth().entra().clientId();
  }

  @Override
  @CircuitBreaker(name = "microsoftEntra", fallbackMethod = "exchangeCodeFallback")
  public TokenResponse exchangeCodeForTokens(String code, String codeVerifier, String redirectUri) {
    log.debug("Exchanging authorization code for tokens with Microsoft Entra");

    try {
      AuthorizationCodeParameters parameters = AuthorizationCodeParameters.builder(
              code,
              new URI(redirectUri))
          .scopes(Collections.singleton("openid profile email"))
          .codeVerifier(codeVerifier)
          .build();

      IAuthenticationResult result = msalClient.acquireToken(parameters).join();

      return new TokenResponse(
          result.idToken(),
          result.accessToken(),
          null, // MSAL doesn't expose refresh token in this flow
          Duration.between(Instant.now(), result.expiresOnDate().toInstant()).getSeconds()
      );

    } catch (CompletionException e) {
      log.error("MSAL execution failed during token exchange", e.getCause());
      throw new OAuth2Exception("Failed to acquire token from Entra ID.", e.getCause());
    } catch (Exception e) {
      log.error("Unexpected error during token exchange", e);
      throw new OAuth2Exception("Token exchange with Entra failed.", e);
    }
  }

  public TokenResponse exchangeCodeFallback(String code, String codeVerifier,
                                            String redirectUri, Throwable ex) {
    log.error("Microsoft Entra circuit breaker is open", ex);
    throw new OAuth2Exception("Microsoft Entra is temporarily unavailable.", ex);
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
