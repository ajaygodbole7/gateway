package com.example.gateway.service;

import com.example.gateway.adapter.idp.IdpClient;
import com.example.gateway.adapter.idp.MicrosoftEntraClient;
import com.example.gateway.adapter.idp.PingIdentityClient;
import com.example.gateway.domain.entity.IdpProvider;
import com.example.gateway.domain.entity.UserPrincipal;
import com.example.gateway.exception.OAuth2Exception;
import com.example.gateway.properties.ApplicationProperties;
import com.example.gateway.security.AuthenticationFailureTracker;
import com.example.gateway.util.JwtValidationUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.Nonce;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.lang.NonNull;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Base64;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;

/**
 * OAuth2 service handling PKCE flow orchestration.
 * Lightweight service that delegates validation to utility classes.
 */
@Slf4j
@Service
public class OAuth2Service {

  private static final String PKCE_STATE_PREFIX = "pkce:state:";
  private static final String USED_CODE_PREFIX = "used_code:";
  private static final String USED_STATE_PREFIX = "used_state:";
  private static final Duration STATE_TTL = Duration.ofMinutes(10);
  private static final Duration REPLAY_KEY_TTL = Duration.ofMinutes(15);
  private static final String ERROR_INVALID_GRANT = "invalid_grant";

  private final RedisTemplate<String, String> redisTemplate;
  private final ObjectMapper objectMapper;
  private final ApplicationProperties properties;
  private final AuthenticationFailureTracker failureTracker;
  private final Map<IdpProvider, IdpClient> idpClients;

  public OAuth2Service(
      RedisTemplate<String, String> redisTemplate,
      ObjectMapper objectMapper,
      ApplicationProperties properties,
      AuthenticationFailureTracker failureTracker,
      PingIdentityClient pingClient,
      MicrosoftEntraClient entraClient) {
    this.redisTemplate = redisTemplate;
    this.objectMapper = objectMapper;
    this.properties = properties;
    this.failureTracker = failureTracker;

    // Build IdP client map
    this.idpClients = new EnumMap<>(IdpProvider.class);
    this.idpClients.put(IdpProvider.PING_IDENTITY, pingClient);
    this.idpClients.put(IdpProvider.MICROSOFT_ENTRA, entraClient);
  }

  /**
   * Generates the authorization URL for OAuth2 login.
   */
  public String generateAuthorizationUrl(@NonNull IdpProvider provider,
                                         @NonNull String returnTo,
                                         @NonNull String clientIp) {
    if (failureTracker.isBlocked(clientIp)) {
      throw new OAuth2Exception("Too many failed attempts from this IP.");
    }

    // Generate PKCE components
    CodeVerifier codeVerifier = new CodeVerifier();
    CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier);
    State state = new State();
    Nonce nonce = new Nonce();

    // Store state for callback validation
    storePkceState(state.getValue(), provider, codeVerifier.getValue(),
                   nonce.getValue(), returnTo, clientIp);

    // Build authorization URL
    IdpClient client = getIdpClient(provider);
    String redirectUri = properties.frontend().url() + "/auth/callback";

    return UriComponentsBuilder.fromHttpUrl(client.getAuthorizationEndpoint())
        .queryParam("response_type", "code")
        .queryParam("client_id", client.getClientId())
        .queryParam("scope", "openid profile email")
        .queryParam("redirect_uri", redirectUri)
        .queryParam("state", state.getValue())
        .queryParam("nonce", nonce.getValue())
        .queryParam("code_challenge", codeChallenge.getValue())
        .queryParam("code_challenge_method", "S256")
        .build()
        .toUriString();
  }

  /**
   * Processes the OAuth2 callback, exchanges code for tokens, and validates them.
   */
  public CallbackResult processCallback(@NonNull String code,
                                        @NonNull String state,
                                        @NonNull String clientIp) {
    try {
      // Prevent replay attacks
      checkAndPreventReplay(code, state);

      // Retrieve and validate state
      PkceStateData stateData = retrieveAndConsumePkceState(state);
      validateCallbackContext(stateData, clientIp);

      // Exchange code for tokens
      IdpClient client = getIdpClient(stateData.provider());
      String redirectUri = properties.frontend().url() + "/auth/callback";

      IdpClient.TokenResponse tokenResponse = client.exchangeCodeForTokens(
          code, stateData.codeVerifier(), redirectUri);

      // Validate ID token using utility
      Jwt jwt = JwtValidationUtils.validateIdToken(
          tokenResponse.idToken(),
          getJwksUri(stateData.provider()),
          getIssuer(stateData.provider()),
          client.getClientId(),
          stateData.nonce()
                                                  );

      // Extract user principal
      UserPrincipal userPrincipal = client.extractUserPrincipal(jwt);

      // Clear failure tracking on success
      failureTracker.clearFailures(clientIp);

      log.info("Successfully authenticated user: {} via {}",
               userPrincipal.userId(), stateData.provider());

      return new CallbackResult(
          userPrincipal,
          tokenResponse.idToken(),
          stateData.provider(),
          stateData.returnTo()
      );

    } catch (OAuth2AuthenticationException e) {
      failureTracker.recordFailure(clientIp);
      throw e;
    } catch (Exception e) {
      failureTracker.recordFailure(clientIp);
      log.error("Callback processing failed", e);
      throw new OAuth2Exception("Callback processing failed: " + e.getMessage(), e);
    }
  }

  // Helper methods

  private void storePkceState(String state, IdpProvider provider, String codeVerifier,
                              String nonce, String returnTo, String clientIp) {
    PkceStateData stateData = new PkceStateData(provider, codeVerifier, nonce, returnTo, clientIp);
    try {
      String json = objectMapper.writeValueAsString(stateData);
      redisTemplate.opsForValue().set(PKCE_STATE_PREFIX + state, json, STATE_TTL);
      log.debug("Stored PKCE state for provider: {}", provider);
    } catch (JsonProcessingException e) {
      throw new OAuth2Exception("Failed to store PKCE state", e);
    }
  }

  private PkceStateData retrieveAndConsumePkceState(String state) {
    String key = PKCE_STATE_PREFIX + state;
    String json = redisTemplate.opsForValue().getAndDelete(key);

    if (json == null) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_INVALID_GRANT, "Invalid or expired state.", null));
    }

    try {
      return objectMapper.readValue(json, PkceStateData.class);
    } catch (JsonProcessingException e) {
      throw new OAuth2Exception("Invalid state data format.", e);
    }
  }

  private void validateCallbackContext(PkceStateData stateData, String currentClientIp) {
    if (!stateData.clientIp().equals(currentClientIp)) {
      log.warn("Client IP mismatch. Original: {}, Current: {}",
               stateData.clientIp(), currentClientIp);
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_INVALID_GRANT, "Client IP mismatch.", null));
    }
  }

  private void checkAndPreventReplay(String code, String state) {
    String codeHash = hashValue(code);
    String codeKey = USED_CODE_PREFIX + codeHash;
    String stateKey = USED_STATE_PREFIX + state;

    // Check if code was already used
    if (Boolean.FALSE.equals(redisTemplate.opsForValue().setIfAbsent(codeKey, "1", REPLAY_KEY_TTL))) {
      log.warn("Authorization code replay detected");
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_INVALID_GRANT, "Authorization code has already been used.", null));
    }

    // Check if state was already used
    if (Boolean.FALSE.equals(redisTemplate.opsForValue().setIfAbsent(stateKey, "1", REPLAY_KEY_TTL))) {
      redisTemplate.delete(codeKey); // Clean up
      log.warn("State replay detected");
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_INVALID_GRANT, "State has already been used.", null));
    }
  }

  private IdpClient getIdpClient(IdpProvider provider) {
    return Optional.ofNullable(idpClients.get(provider))
        .orElseThrow(() -> new OAuth2Exception(
            "No IdpClient configured for provider: " + provider));
  }

  private String getJwksUri(IdpProvider provider) {
    return switch (provider) {
      case PING_IDENTITY -> properties.auth().ping().jwksUri();
      case MICROSOFT_ENTRA -> properties.auth().entra().validationUri() + "/discovery/v2.0/keys";
    };
  }

  private String getIssuer(IdpProvider provider) {
    return switch (provider) {
      case PING_IDENTITY -> properties.auth().ping().issuerUri();
      case MICROSOFT_ENTRA -> properties.auth().entra().issuerUri();
    };
  }

  private String hashValue(String value) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    } catch (NoSuchAlgorithmException e) {
      throw new OAuth2Exception("SHA-256 algorithm not available", e);
    }
  }

  // DTOs

  private record PkceStateData(
      IdpProvider provider,
      String codeVerifier,
      String nonce,
      String returnTo,
      String clientIp
  ) {}

  public record CallbackResult(
      UserPrincipal userPrincipal,
      String idToken,
      IdpProvider provider,
      String returnTo
  ) {}
}
