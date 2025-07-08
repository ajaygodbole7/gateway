package com.example.gateway.adapter.idp;

import com.example.gateway.adapter.keyvault.client.AzureKeyVaultClient;
import com.example.gateway.domain.entity.UserPrincipal;
import com.example.gateway.exception.OAuth2Exception;
import com.example.gateway.properties.ApplicationProperties;
import com.microsoft.aad.msal4j.*;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Component;

import java.net.MalformedURLException;
import java.net.URI;
import java.time.Duration;
import java.util.Collections;
import java.util.concurrent.ExecutionException;

@Slf4j
@Component
public class MicrosoftEntraClient implements IdpClient {

  private static final String CIRCUIT_BREAKER_NAME = "microsoftEntra";
  private static final String CLIENT_SECRET_NAME = "entra-client-secret";

  private final ApplicationProperties properties;
  private final JwtDecoder jwtDecoder;
  private final ConfidentialClientApplication msalClient;

  public MicrosoftEntraClient(ApplicationProperties properties, AzureKeyVaultClient keyVaultClient, JwtDecoder jwtDecoder) throws MalformedURLException {
    this.properties = properties;
    this.jwtDecoder = jwtDecoder;
    String clientSecret = keyVaultClient.getSecret(CLIENT_SECRET_NAME);
    this.msalClient = ConfidentialClientApplication.builder(
            properties.auth().entra().clientId(),
            ClientCredentialFactory.createFromSecret(clientSecret))
        .authority(properties.auth().entra().authority())
        .build();
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
  @CircuitBreaker(name = CIRCUIT_BREAKER_NAME, fallbackMethod = "exchangeCodeFallback")
  public TokenResponse exchangeCodeForTokens(String code, String codeVerifier, String redirectUri) {
    log.debug("Exchanging authorization code for tokens with Microsoft Entra using MSAL4J.");
    try {
      AuthorizationCodeParameters parameters = AuthorizationCodeParameters.builder(
              code,
              new URI(redirectUri))
          .scopes(Collections.singleton("openid profile email"))
          .codeVerifier(codeVerifier)
          .build();

      // .join() makes the asynchronous call synchronous
      IAuthenticationResult result = msalClient.acquireToken(parameters).join();

      return new TokenResponse(
          result.idToken(),
          result.accessToken(),
          null, // MSAL4J does not typically expose the refresh token directly here
          Duration.between(java.time.Instant.now(), result.expiresOnDate().toInstant()).getSeconds()
      );
    } catch (ExecutionException e) {
      // This often wraps MsalServiceException or MsalClientException
      log.error("MSAL execution failed during token exchange with Entra", e.getCause());
      throw new OAuth2Exception("Failed to acquire token from Entra ID.", e.getCause());
    }
    catch (Exception e) {
      log.error("An unexpected error occurred during token exchange with Entra", e);
      throw new OAuth2Exception("Token exchange with Entra failed.", e);
    }
  }

  public TokenResponse exchangeCodeFallback(String code, String codeVerifier, String redirectUri, Throwable ex) {
    log.error("Microsoft Entra circuit breaker is open during token exchange.", ex);
    throw new OAuth2Exception("Microsoft Entra is temporarily unavailable.", ex);
  }

  @Override
  public Jwt validateIdToken(String idToken) {
    try {
      return jwtDecoder.decode(idToken);
    } catch (Exception e) {
      throw new OAuth2Exception("Invalid ID token from Entra", e);
    }
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
