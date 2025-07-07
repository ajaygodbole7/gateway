package com.example.gateway.service;

import com.example.gateway.adapter.keyvault.client.AzureKeyVaultClient;
import com.example.gateway.domain.entity.IdpProvider;
import com.example.gateway.domain.entity.UserPrincipal;
import com.example.gateway.exception.OAuth2Exception;
import com.example.gateway.properties.ApplicationProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * OAuth2 Service with full PKCE and OIDC support
 *
 * Implements:
 * - RFC 7636 (PKCE) with proper error handling
 * - OpenID Connect Core 1.0
 * - Multi-IdP support (Ping Identity and Microsoft Entra)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2Service {

  private static final String OAUTH_STATE_PREFIX = "oauth:state:";
  private static final String OAUTH_CODE_USED_PREFIX = "oauth:code:used:";
  private static final Duration STATE_TTL = Duration.ofMinutes(10);
  private static final Duration CODE_USED_TTL = Duration.ofMinutes(15);
  // OAuth2/OIDC error codes
  private static final String INVALID_REQUEST = "invalid_request";
  private static final String INVALID_GRANT = "invalid_grant";
  private static final String INVALID_TOKEN = "invalid_token";
  private static final String TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";
  // OIDC configuration defaults
  private static final long DEFAULT_MAX_AUTHENTICATION_AGE = 3600; // 1 hour
  private static final boolean DEFAULT_USE_REQUEST_OBJECT = false;
  private static final String DEFAULT_ACR_VALUES = "";
  private final RedisTemplate<String, String> redisTemplate;
  private final JwtDecoder jwtDecoder;
  private final AzureKeyVaultClient keyVaultClient;
  private final ObjectMapper objectMapper;
  private final ApplicationProperties properties;

  /**
   * Generate OAuth2 authorization request with full OIDC support
   */
  public OAuth2AuthorizationRequest generateAuthorizationRequest(
      @NonNull IdpProvider provider,
      @NonNull String returnTo,
      @Nullable String prompt,
      @Nullable Long maxAge,
      @Nullable String loginHint,
      @Nullable String acrValues) {

    // Validate return path
    if (!isValidReturnPath(returnTo)) {
      log.warn("Invalid return path requested: {}, using default", returnTo);
      returnTo = "/dashboard";
    }

    // Generate PKCE parameters with configured length
    CodeVerifier codeVerifier = new CodeVerifier();
    CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier);

    String state = UUID.randomUUID().toString();
    String nonce = UUID.randomUUID().toString();

    // Create comprehensive state data
    Map<String, Object> stateDataMap = new HashMap<>();
    stateDataMap.put("codeVerifier", codeVerifier.getValue());
    stateDataMap.put("nonce", nonce);
    stateDataMap.put("returnTo", returnTo);
    stateDataMap.put("provider", provider.name());
    stateDataMap.put("createdAt", System.currentTimeMillis());
    stateDataMap.put("maxAge", maxAge);
    stateDataMap.put("acrValues", acrValues != null ? acrValues : DEFAULT_ACR_VALUES);

    try {
      String stateData = objectMapper.writeValueAsString(stateDataMap);
      redisTemplate.opsForValue().set(OAUTH_STATE_PREFIX + state, stateData, STATE_TTL);
      log.debug("Stored OAuth state for provider {} with state: {}", provider, state);
    } catch (Exception e) {
      throw new OAuth2Exception("Failed to store state data", e);
    }

    // Get provider-specific configuration
    String clientId = getClientId(provider);
    String authorizationUri = getAuthorizationUri(provider);
    String redirectUri = properties.frontend().url() + "/auth/callback";

    // Build authorization request
    var requestBuilder = OAuth2AuthorizationRequest.authorizationCode()
        .clientId(clientId)
        .authorizationUri(authorizationUri)
        .redirectUri(redirectUri)
        .scopes(Set.of("openid", "profile", "email"))
        .state(state);

    // Add PKCE and OIDC parameters
    Map<String, Object> additionalParams = new HashMap<>();
    additionalParams.put("nonce", nonce);
    additionalParams.put(PkceParameterNames.CODE_CHALLENGE, codeChallenge.getValue());
    additionalParams.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
    additionalParams.put("response_mode", "query");

    // OIDC specific parameters
    if (prompt != null && !prompt.isEmpty()) {
      additionalParams.put("prompt", prompt);
    }
    if (maxAge != null) {
      additionalParams.put("max_age", maxAge.toString());
    }
    if (loginHint != null && !loginHint.isEmpty()) {
      additionalParams.put("login_hint", loginHint);
    }
    if (acrValues != null && !acrValues.isEmpty()) {
      additionalParams.put("acr_values", acrValues);
    }

    requestBuilder.additionalParameters(additionalParams);

    return requestBuilder.build();
  }

  /**
   * Generate authorization request with default parameters
   */
  public OAuth2AuthorizationRequest generateAuthorizationRequest(
      @NonNull IdpProvider provider,
      @NonNull String returnTo) {
    return generateAuthorizationRequest(provider, returnTo, null, null, null, DEFAULT_ACR_VALUES);
  }

  /**
   * Exchange authorization code for tokens with enhanced error handling
   */
  public String exchangeCodeForToken(@NonNull String code, @NonNull String state) {
    // Check if code was already used (replay attack prevention)
    String codeHash = hashCode(code);
    String codeUsedKey = OAUTH_CODE_USED_PREFIX + codeHash;

    Boolean wasSet = redisTemplate.opsForValue().setIfAbsent(codeUsedKey, "1", CODE_USED_TTL);
    if (Boolean.FALSE.equals(wasSet)) {
      log.error("Authorization code replay attempt detected for code hash: {}", codeHash);
      throw new OAuth2AuthenticationException(
          new OAuth2Error(INVALID_GRANT, "Authorization code already used", null));
    }

    // Retrieve and validate state
    String stateDataJson = redisTemplate.opsForValue().getAndDelete(OAUTH_STATE_PREFIX + state);
    if (stateDataJson == null) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(INVALID_GRANT,
                          "The provided authorization code is invalid, expired, revoked, " +
                              "does not match the redirection URI used in the authorization request, " +
                              "or was issued to another client", null));
    }

    Map<String, Object> stateData;
    try {
      stateData = objectMapper.readValue(stateDataJson, Map.class);
    } catch (Exception e) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(INVALID_GRANT, "Invalid state data", null));
    }

    // Validate state age
    long createdAt = ((Number) stateData.get("createdAt")).longValue();
    if (System.currentTimeMillis() - createdAt > STATE_TTL.toMillis()) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(INVALID_GRANT, "State expired", null));
    }

    String codeVerifier = (String) stateData.get("codeVerifier");
    if (codeVerifier == null || codeVerifier.isEmpty()) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(INVALID_GRANT, "Invalid PKCE verification", null));
    }

    IdpProvider provider = IdpProvider.valueOf((String) stateData.get("provider"));

    try {
      // Create token request using Nimbus
      AuthorizationCode authCode = new AuthorizationCode(code);
      URI redirectUri = new URI(properties.frontend().url() + "/auth/callback");
      CodeVerifier verifier = new CodeVerifier(codeVerifier);

      AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant(
          authCode, redirectUri, verifier);

      ClientID clientID = new ClientID(getClientId(provider));
      Secret clientSecret = new Secret(getClientSecret(provider));
      ClientSecretBasic clientAuth = new ClientSecretBasic(clientID, clientSecret);

      URI tokenEndpoint = new URI(getTokenUri(provider));
      TokenRequest tokenRequest = new TokenRequest(
          tokenEndpoint, clientAuth, codeGrant);

      // Send token request
      HTTPResponse httpResponse = tokenRequest.toHTTPRequest().send();
      TokenResponse tokenResponse = OIDCTokenResponseParser.parse(httpResponse);

      if (!tokenResponse.indicatesSuccess()) {
        handleTokenErrorResponse(tokenResponse);
      }

      OIDCTokenResponse oidcResponse = (OIDCTokenResponse) tokenResponse;

      // Store tokens in state data for potential use
      stateData.put("idToken", oidcResponse.getOIDCTokens().getIDToken().serialize());
      if (oidcResponse.getOIDCTokens().getAccessToken() != null) {
        stateData.put("accessToken", oidcResponse.getOIDCTokens().getAccessToken().getValue());
      }
      if (oidcResponse.getOIDCTokens().getRefreshToken() != null) {
        stateData.put("refreshToken", oidcResponse.getOIDCTokens().getRefreshToken().getValue());
      }

      // Store updated state temporarily for validation
      String updatedStateJson = objectMapper.writeValueAsString(stateData);
      redisTemplate.opsForValue().set(OAUTH_STATE_PREFIX + state, updatedStateJson, Duration.ofMinutes(5));

      log.info("Successfully exchanged code for tokens for provider: {}", provider);
      return oidcResponse.getOIDCTokens().getIDToken().serialize();

    } catch (URISyntaxException | IOException e) {
      log.error("Token exchange failed for provider: {}", provider, e);
      throw new OAuth2AuthenticationException(
          new OAuth2Error(TEMPORARILY_UNAVAILABLE, "Service temporarily unavailable", null));
    } catch (OAuth2AuthenticationException e) {
      throw e;
    } catch (Exception e) {
      log.error("Unexpected error during token exchange for provider: {}", provider, e);
      throw new OAuth2AuthenticationException(
          new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "Token exchange failed", null));
    }
  }

  /**
   * Validate ID token with comprehensive OIDC checks
   */
  public UserPrincipal validateIdToken(@NonNull String idToken, @NonNull String state) {
    // Retrieve state data
    String stateDataJson = redisTemplate.opsForValue().get(OAUTH_STATE_PREFIX + state);
    if (stateDataJson == null) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(INVALID_REQUEST, "Invalid state", null));
    }

    Map<String, Object> stateData;
    try {
      stateData = objectMapper.readValue(stateDataJson, Map.class);
    } catch (Exception e) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(INVALID_REQUEST, "Invalid state data", null));
    }

    String expectedNonce = (String) stateData.get("nonce");
    long authRequestTime = ((Number) stateData.get("createdAt")).longValue();
    Long requestedMaxAge = stateData.get("maxAge") != null ?
        ((Number) stateData.get("maxAge")).longValue() : null;
    String requestedAcrValues = (String) stateData.get("acrValues");
    IdpProvider provider = IdpProvider.valueOf((String) stateData.get("provider"));

    try {
      // Decode and validate JWT
      Jwt jwt = jwtDecoder.decode(idToken);

      // Validate audience
      List<String> audiences = jwt.getAudience();
      String expectedClientId = getClientId(provider);

      if (audiences == null || !audiences.contains(expectedClientId)) {
        throw new OAuth2AuthenticationException(
            new OAuth2Error(INVALID_TOKEN, "Invalid audience", null));
      }

      // Multiple audiences check - verify azp
      if (audiences.size() > 1) {
        String azp = jwt.getClaimAsString("azp");
        if (!expectedClientId.equals(azp)) {
          throw new OAuth2AuthenticationException(
              new OAuth2Error(INVALID_TOKEN, "Invalid authorized party", null));
        }
      }

      // Nonce validation
      String tokenNonce = jwt.getClaimAsString("nonce");
      if (!expectedNonce.equals(tokenNonce)) {
        throw new OAuth2AuthenticationException(
            new OAuth2Error(INVALID_TOKEN, "Invalid nonce", null));
      }

      // auth_time validation
      Long authTime = jwt.getClaim("auth_time");
      if (authTime != null) {
        long currentTime = System.currentTimeMillis() / 1000;

        // Check max_age if requested
        if (requestedMaxAge != null) {
          long timeSinceAuth = currentTime - authTime;
          if (timeSinceAuth > requestedMaxAge) {
            throw new OAuth2AuthenticationException(
                new OAuth2Error(INVALID_TOKEN,
                                "Authentication too old, max_age exceeded", null));
          }
        }

        // Check against configured maximum
        long timeSinceAuth = currentTime - authTime;
        if (timeSinceAuth > DEFAULT_MAX_AUTHENTICATION_AGE) {
          throw new OAuth2AuthenticationException(
              new OAuth2Error(INVALID_TOKEN, "Authentication too old", null));
        }
      }

      // ACR validation
      if (requestedAcrValues != null && !requestedAcrValues.isEmpty()) {
        String acr = jwt.getClaimAsString("acr");
        List<String> requestedAcrs = Arrays.asList(requestedAcrValues.split(" "));
        if (acr == null || !requestedAcrs.contains(acr)) {
          log.warn("ACR mismatch. Requested: {}, Received: {}", requestedAcrValues, acr);
        }
      }

      // Additional security checks
      validateAdditionalClaims(jwt);

      // Extract user information
      return new UserPrincipal(
          jwt.getSubject(),
          jwt.getClaimAsString("preferred_username"),
          jwt.getClaimAsString("email"),
          jwt.getClaimAsString("given_name"),
          jwt.getClaimAsString("family_name"),
          System.currentTimeMillis(),
          properties.security().session().slidingWindowMinutes() * 60L
      );

    } catch (JwtException e) {
      log.error("JWT validation failed", e);
      throw new OAuth2AuthenticationException(
          new OAuth2Error(INVALID_TOKEN, "Invalid ID token", null));
    } catch (OAuth2AuthenticationException e) {
      throw e;
    } catch (Exception e) {
      log.error("Token validation failed", e);
      throw new OAuth2AuthenticationException(
          new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "Token validation failed", null));
    } finally {
      // Clean up state after validation
      redisTemplate.delete(OAUTH_STATE_PREFIX + state);
    }
  }

  /**
   * Build authorization URL
   */
  public String buildAuthorizationUrl(@NonNull OAuth2AuthorizationRequest request) {
    return UriComponentsBuilder
        .fromUriString(request.getAuthorizationUri())
        .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, "code")
        .queryParam(OAuth2ParameterNames.CLIENT_ID, request.getClientId())
        .queryParam(OAuth2ParameterNames.SCOPE, String.join(" ", request.getScopes()))
        .queryParam(OAuth2ParameterNames.STATE, request.getState())
        .queryParam(OAuth2ParameterNames.REDIRECT_URI, request.getRedirectUri())
        .queryParams(request.getAdditionalParameters())
        .build()
        .toUriString();
  }

  /**
   * Get return URL from state
   */
  public String getReturnUrl(@NonNull String state) {
    try {
      String stateDataJson = redisTemplate.opsForValue().get(OAUTH_STATE_PREFIX + state);
      if (stateDataJson != null) {
        Map<String, Object> stateData = objectMapper.readValue(stateDataJson, Map.class);
        String returnTo = (String) stateData.get("returnTo");
        return returnTo != null && isValidReturnPath(returnTo) ? returnTo : "/dashboard";
      }
    } catch (Exception e) {
      log.error("Failed to retrieve return URL", e);
    }
    return "/dashboard";
  }

  /**
   * Build end session URL for OIDC logout
   */
  public String buildEndSessionUrl(@NonNull IdpProvider provider,
                                   @Nullable String idToken,
                                   @Nullable String postLogoutRedirectUri,
                                   @Nullable String state) {
    // For now, return to home. In future, implement provider-specific logout
    log.info("Building end session URL for provider: {}", provider);
    return postLogoutRedirectUri != null ? postLogoutRedirectUri : "/";
  }

  /**
   * Validate additional security claims
   */
  private void validateAdditionalClaims(Jwt jwt) {
    // Check for required claims
    if (jwt.getSubject() == null || jwt.getSubject().isEmpty()) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(INVALID_TOKEN, "Missing subject claim", null));
    }

    // Validate issued at time
    Instant issuedAt = jwt.getIssuedAt();
    if (issuedAt != null && issuedAt.isAfter(Instant.now().plusSeconds(60))) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(INVALID_TOKEN, "Token issued in the future", null));
    }
  }

  /**
   * Handle token error response
   */
  private void handleTokenErrorResponse(TokenResponse errorResponse) {
    com.nimbusds.oauth2.sdk.ErrorObject error = errorResponse.toErrorResponse().getErrorObject();

    String errorCode = error.getCode();
    String errorDescription = error.getDescription();

    log.error("Token error response: {} - {}", errorCode, errorDescription);

    // Map to appropriate OAuth2 error
    if ("invalid_grant".equals(errorCode)) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(INVALID_GRANT, errorDescription, null));
    }

    throw new OAuth2AuthenticationException(
        new OAuth2Error(errorCode, errorDescription, error.getURI() != null ?
            error.getURI().toString() : null));
  }

  /**
   * Get client ID based on provider
   */
  private String getClientId(IdpProvider provider) {
    return switch (provider) {
      case PING_IDENTITY -> properties.auth().ping().clientId();
      case MICROSOFT_ENTRA -> properties.auth().entra().clientId();
    };
  }

  /**
   * Get authorization URI based on provider
   */
  private String getAuthorizationUri(IdpProvider provider) {
    return switch (provider) {
      case PING_IDENTITY -> properties.auth().ping().authorizationUri();
      case MICROSOFT_ENTRA -> properties.auth().entra().authority() + "/oauth2/v2.0/authorize";
    };
  }

  /**
   * Get token URI based on provider
   */
  private String getTokenUri(IdpProvider provider) {
    return switch (provider) {
      case PING_IDENTITY -> properties.auth().ping().tokenUri();
      case MICROSOFT_ENTRA -> properties.auth().entra().authority() + "/oauth2/v2.0/token";
    };
  }

  /**
   * Get client secret from Key Vault based on provider
   */
  private String getClientSecret(IdpProvider provider) {
    return switch (provider) {
      case PING_IDENTITY -> keyVaultClient.getSecret("ping-client-secret");
      case MICROSOFT_ENTRA -> keyVaultClient.getSecret("entra-client-secret");
    };
  }

  /**
   * Check if return path is valid
   */
  private boolean isValidReturnPath(String path) {
    return properties.auth().allowedReturnPaths().contains(path);
  }

  /**
   * Hash authorization code for storage
   */
  private String hashCode(String code) {
    try {
      var digest = java.security.MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(code.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(hash);
    } catch (Exception e) {
      throw new OAuth2Exception("Failed to hash code", e);
    }
  }

  /**
   * Clean up expired state data - runs every hour
   * Note: This is a safety mechanism. Redis TTL should handle most cleanup.
   */
  @Scheduled(fixedDelay = 1, timeUnit = TimeUnit.HOURS)
  public void cleanupExpiredState() {
    log.debug("Running OAuth state cleanup task");
    try {
      Set<String> keys = redisTemplate.keys(OAUTH_STATE_PREFIX + "*");
      if (keys != null && !keys.isEmpty()) {
        int cleaned = 0;
        for (String key : keys) {
          Long ttl = redisTemplate.getExpire(key);
          if (ttl == null || ttl <= 0) {
            redisTemplate.delete(key);
            cleaned++;
          }
        }
        if (cleaned > 0) {
          log.info("Cleaned up {} expired OAuth state entries", cleaned);
        }
      }
    } catch (Exception e) {
      log.error("Error during OAuth state cleanup", e);
    }
  }
}
