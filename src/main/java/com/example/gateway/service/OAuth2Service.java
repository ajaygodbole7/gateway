package com.example.gateway.service;

import com.example.gateway.adapter.idp.IdpClient;
import com.example.gateway.adapter.idp.MicrosoftEntraClient;
import com.example.gateway.adapter.idp.PingIdentityClient;
import com.example.gateway.domain.entity.IdpProvider;
import com.example.gateway.domain.entity.UserPrincipal;
import com.example.gateway.exception.OAuth2Exception;
import com.example.gateway.properties.ApplicationProperties;
import com.example.gateway.security.AuthenticationFailureTracker;
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
 * OAuth2 orchestration service that uses a manually constructed map of IdP clients
 * to ensure clean dependency injection and clear logic.
 */
@Slf4j
@Service
public class OAuth2Service {

  // --- Constants ---
  private static final String PKCE_STATE_PREFIX = "pkce:";
  private static final String USED_CODE_PREFIX = "used_code:";
  private static final String USED_STATE_PREFIX = "used_state:";
  private static final Duration STATE_TTL = Duration.ofMinutes(10);
  private static final Duration REPLAY_KEY_TTL = Duration.ofMinutes(15);
  private static final String ERROR_INVALID_GRANT = "invalid_grant";
  private static final String ERROR_INVALID_TOKEN = "invalid_token";

  // --- Injected Dependencies ---
  private final RedisTemplate<String, String> redisTemplate;
  private final ObjectMapper objectMapper;
  private final ApplicationProperties properties;
  private final AuthenticationFailureTracker failureTracker;
  private final Map<IdpProvider, IdpClient> idpClients; // This map will be constructed manually

  /**
   * DTO for successful authentication results.
   */
  public record AuthSuccessResult(UserPrincipal principal, String idToken, IdpProvider provider, String returnTo) {}

  /**
   * Constructs the OAuth2Service, injecting individual client implementations
   * and manually building the provider-to-client map. This is the correct
   * pattern for handling dependency injection of strategies keyed by an enum.
   */
  public OAuth2Service(
      RedisTemplate<String, String> redisTemplate,
      ObjectMapper objectMapper,
      ApplicationProperties properties,
      AuthenticationFailureTracker failureTracker,
      PingIdentityClient pingClient, // Inject the concrete Ping client
      MicrosoftEntraClient entraClient // Inject the concrete Entra client
                      ) {
    this.redisTemplate = redisTemplate;
    this.objectMapper = objectMapper;
    this.properties = properties;
    this.failureTracker = failureTracker;

    // Manually construct the map
    this.idpClients = new EnumMap<>(IdpProvider.class);
    this.idpClients.put(IdpProvider.PING_IDENTITY, pingClient);
    this.idpClients.put(IdpProvider.MICROSOFT_ENTRA, entraClient);
  }

  public String generateAuthorizationUrl(@NonNull IdpProvider provider, @NonNull String returnTo, @NonNull String clientIp) {
    if (failureTracker.isBlocked(clientIp)) {
      throw new OAuth2Exception("Too many failed attempts from this IP.");
    }

    CodeVerifier codeVerifier = new CodeVerifier();
    CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier);
    State state = new State();
    Nonce nonce = new Nonce();

    storePkceState(state.getValue(), provider, codeVerifier.getValue(), nonce.getValue(), returnTo, clientIp);

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
        .build().toUriString();
  }

  public AuthSuccessResult processCallback(@NonNull String code, @NonNull String state, @NonNull String clientIp) {
    try {
      checkAndPreventReplay(code, state);
      PkceStateData stateData = retrieveAndConsumePkceState(state);
      validateCallbackContext(stateData, clientIp);

      IdpClient client = getIdpClient(stateData.provider());
      String redirectUri = properties.frontend().url() + "/auth/callback";

      IdpClient.TokenResponse tokenResponse = client.exchangeCodeForTokens(code, stateData.codeVerifier(), redirectUri);

      Jwt jwt = client.validateIdToken(tokenResponse.idToken());
      validateOidcClaims(jwt, stateData.nonce());

      UserPrincipal userPrincipal = client.extractUserPrincipal(jwt);

      failureTracker.clearFailures(clientIp);

      return new AuthSuccessResult(userPrincipal, tokenResponse.idToken(), stateData.provider(), stateData.returnTo());
    } catch (Exception e) {
      failureTracker.recordFailure(clientIp);
      if (e instanceof OAuth2Exception || e instanceof OAuth2AuthenticationException) {
        throw e;
      }
      throw new OAuth2Exception("Callback processing failed.", e);
    }
  }

  // --- All private helper methods remain unchanged ---

  private void storePkceState(String state, IdpProvider provider, String codeVerifier, String nonce, String returnTo, String clientIp) {
    PkceStateData stateData = new PkceStateData(provider, codeVerifier, nonce, returnTo, clientIp);
    try {
      String json = objectMapper.writeValueAsString(stateData);
      redisTemplate.opsForValue().set(PKCE_STATE_PREFIX + state, json, STATE_TTL);
    } catch (JsonProcessingException e) {
      throw new OAuth2Exception("Failed to store PKCE state", e);
    }
  }

  private PkceStateData retrieveAndConsumePkceState(String state) {
    String json = redisTemplate.opsForValue().getAndDelete(PKCE_STATE_PREFIX + state);
    if (json == null) {
      throw new OAuth2AuthenticationException(new OAuth2Error(ERROR_INVALID_GRANT, "Invalid or expired state.", null));
    }
    try {
      return objectMapper.readValue(json, PkceStateData.class);
    } catch (JsonProcessingException e) {
      throw new OAuth2Exception("Invalid state data format.", e);
    }
  }

  private void validateCallbackContext(PkceStateData stateData, String currentClientIp) {
    if (!stateData.clientIp().equals(currentClientIp)) {
      throw new OAuth2AuthenticationException(new OAuth2Error(ERROR_INVALID_GRANT, "Client IP mismatch.", null));
    }
  }

  private void checkAndPreventReplay(String code, String state) {
    String codeHash = hashValue(code);
    String codeKey = USED_CODE_PREFIX + codeHash;
    String stateKey = USED_STATE_PREFIX + state;

    if (Boolean.FALSE.equals(redisTemplate.opsForValue().setIfAbsent(codeKey, "1", REPLAY_KEY_TTL))) {
      throw new OAuth2AuthenticationException(new OAuth2Error(ERROR_INVALID_GRANT, "Authorization code has already been used.", null));
    }
    if (Boolean.FALSE.equals(redisTemplate.opsForValue().setIfAbsent(stateKey, "1", REPLAY_KEY_TTL))) {
      redisTemplate.delete(codeKey);
      throw new OAuth2AuthenticationException(new OAuth2Error(ERROR_INVALID_GRANT, "State has already been used.", null));
    }
  }

  private void validateOidcClaims(Jwt jwt, String expectedNonce) {
    String tokenNonce = jwt.getClaimAsString("nonce");
    if (tokenNonce == null || !tokenNonce.equals(expectedNonce)) {
      throw new OAuth2AuthenticationException(new OAuth2Error(ERROR_INVALID_TOKEN, "Nonce validation failed.", null));
    }
  }

  private IdpClient getIdpClient(IdpProvider provider) {
    return Optional.ofNullable(idpClients.get(provider))
        .orElseThrow(() -> new OAuth2Exception("FATAL: No IdpClient bean is configured for provider: " + provider));
  }

  private String hashValue(String value) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    } catch (NoSuchAlgorithmException e) {
      throw new OAuth2Exception("SHA-256 algorithm not available for hashing.", e);
    }
  }

  private record PkceStateData(IdpProvider provider, String codeVerifier, String nonce, String returnTo, String clientIp) {}
}
