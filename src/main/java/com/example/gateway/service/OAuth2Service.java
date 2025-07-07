package com.example.gateway.service;

import com.example.gateway.adapter.keyvault.client.AzureKeyVaultClient;
import com.example.gateway.domain.entity.IdpProvider;
import com.example.gateway.domain.entity.UserPrincipal;
import com.example.gateway.exception.OAuth2Exception;
import com.example.gateway.properties.ApplicationProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ParseException;
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
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

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

  // Redis Key Prefixes
  private static final String OAUTH_STATE_PREFIX = "oauth:state:";
  private static final String OAUTH_CODE_USED_PREFIX = "oauth:code:used:";

  // TTL Constants
  private static final Duration STATE_TTL = Duration.ofMinutes(10);
  private static final Duration CODE_USED_TTL = Duration.ofMinutes(15);
  private static final Duration TEMP_STATE_TTL = Duration.ofMinutes(5);

  // OAuth2/OIDC Error Codes
  private static final String ERROR_INVALID_REQUEST = "invalid_request";
  private static final String ERROR_INVALID_GRANT = "invalid_grant";
  private static final String ERROR_INVALID_TOKEN = "invalid_token";
  private static final String ERROR_TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";
  private static final String ERROR_SERVER_ERROR = "server_error";

  // OIDC Configuration Defaults
  private static final long DEFAULT_MAX_AUTHENTICATION_AGE_SECONDS = 3600; // 1 hour
  private static final String DEFAULT_ACR_VALUES = "";
  private static final String DEFAULT_RETURN_PATH = "/dashboard";
  private static final String DEFAULT_RESPONSE_MODE = "query";
  private static final String DEFAULT_REDIRECT_PATH = "/auth/callback";

  // OIDC Scopes
  private static final Set<String> DEFAULT_SCOPES = Set.of("openid", "profile", "email");

  // State Data Field Names
  private static final String STATE_FIELD_CODE_VERIFIER = "codeVerifier";
  private static final String STATE_FIELD_NONCE = "nonce";
  private static final String STATE_FIELD_RETURN_TO = "returnTo";
  private static final String STATE_FIELD_PROVIDER = "provider";
  private static final String STATE_FIELD_CREATED_AT = "createdAt";
  private static final String STATE_FIELD_MAX_AGE = "maxAge";
  private static final String STATE_FIELD_ACR_VALUES = "acrValues";
  private static final String STATE_FIELD_ID_TOKEN = "idToken";
  private static final String STATE_FIELD_ACCESS_TOKEN = "accessToken";
  private static final String STATE_FIELD_REFRESH_TOKEN = "refreshToken";

  // JWT Claim Names
  private static final String CLAIM_NONCE = "nonce";
  private static final String CLAIM_AZP = "azp";
  private static final String CLAIM_AUTH_TIME = "auth_time";
  private static final String CLAIM_ACR = "acr";
  private static final String CLAIM_PREFERRED_USERNAME = "preferred_username";
  private static final String CLAIM_EMAIL = "email";
  private static final String CLAIM_GIVEN_NAME = "given_name";
  private static final String CLAIM_FAMILY_NAME = "family_name";

  // OIDC Parameters
  private static final String PARAM_PROMPT = "prompt";
  private static final String PARAM_MAX_AGE = "max_age";
  private static final String PARAM_LOGIN_HINT = "login_hint";
  private static final String PARAM_ACR_VALUES = "acr_values";
  private static final String PARAM_NONCE = "nonce";
  private static final String PARAM_RESPONSE_MODE = "response_mode";

  // Hash Algorithm
  private static final String HASH_ALGORITHM = "SHA-256";

  // Scheduling Constants
  private static final long CLEANUP_INTERVAL_HOURS = 1;

  // Key Vault Secret Names
  private static final String PING_CLIENT_SECRET_NAME = "ping-client-secret";
  private static final String ENTRA_CLIENT_SECRET_NAME = "entra-client-secret";

  // URL Paths
  private static final String ENTRA_AUTHORIZE_PATH = "/oauth2/v2.0/authorize";
  private static final String ENTRA_TOKEN_PATH = "/oauth2/v2.0/token";

  // Dependencies
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
    String validatedReturnPath = validateAndNormalizeReturnPath(returnTo);

    // Generate PKCE parameters
    CodeVerifier codeVerifier = new CodeVerifier();
    CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier);

    // Generate unique identifiers
    String state = UUID.randomUUID().toString();
    String nonce = UUID.randomUUID().toString();

    // Store state data
    storeStateData(state, codeVerifier, nonce, validatedReturnPath, provider, maxAge, acrValues);

    // Build authorization request
    return buildAuthorizationRequest(
        provider, state, codeChallenge, nonce,
        prompt, maxAge, loginHint, acrValues
                                    );
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
    // Prevent code replay attacks
    preventCodeReplay(code);

    // Retrieve and validate state
    Map<String, Object> stateData = retrieveAndValidateState(state);

    // Extract required data from state
    String codeVerifier = (String) stateData.get(STATE_FIELD_CODE_VERIFIER);
    IdpProvider provider = IdpProvider.valueOf((String) stateData.get(STATE_FIELD_PROVIDER));

    try {
      // Exchange code for tokens
      OIDCTokenResponse tokenResponse = performTokenExchange(code, codeVerifier, provider);

      // Store tokens in state for further processing
      storeTokensInState(state, stateData, tokenResponse);

      log.info("Successfully exchanged code for tokens for provider: {}", provider);
      return tokenResponse.getOIDCTokens().getIDToken().serialize();

    } catch (OAuth2AuthenticationException e) {
      throw e;
    } catch (URISyntaxException | IOException e) {
      log.error("Token exchange failed for provider: {}", provider, e);
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_TEMPORARILY_UNAVAILABLE, "Service temporarily unavailable", null));
    } catch (Exception e) {
      log.error("Unexpected error during token exchange for provider: {}", provider, e);
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_SERVER_ERROR, "Token exchange failed", null));
    }
  }

  /**
   * Validate ID token with comprehensive OIDC checks
   */
  public UserPrincipal validateIdToken(@NonNull String idToken, @NonNull String state) {
    // Retrieve state data for validation context
    Map<String, Object> stateData = retrieveStateData(state);

    // Extract validation parameters
    String expectedNonce = (String) stateData.get(STATE_FIELD_NONCE);
    Long requestedMaxAge = stateData.get(STATE_FIELD_MAX_AGE) != null ?
        ((Number) stateData.get(STATE_FIELD_MAX_AGE)).longValue() : null;
    String requestedAcrValues = (String) stateData.get(STATE_FIELD_ACR_VALUES);
    IdpProvider provider = IdpProvider.valueOf((String) stateData.get(STATE_FIELD_PROVIDER));

    try {
      // Decode and validate JWT
      Jwt jwt = jwtDecoder.decode(idToken);

      // Perform all OIDC validations
      validateJwtClaims(jwt, provider, expectedNonce, requestedMaxAge, requestedAcrValues);

      // Extract user information
      UserPrincipal userPrincipal = extractUserPrincipal(jwt);

      // Clean up state after successful validation
      redisTemplate.delete(OAUTH_STATE_PREFIX + state);

      return userPrincipal;

    } catch (JwtException e) {
      log.error("JWT validation failed", e);
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_INVALID_TOKEN, "Invalid ID token", null));
    } catch (OAuth2AuthenticationException e) {
      throw e;
    } catch (Exception e) {
      log.error("Token validation failed", e);
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_SERVER_ERROR, "Token validation failed", null));
    }
  }

  /**
   * Build authorization URL
   */
  public String buildAuthorizationUrl(@NonNull OAuth2AuthorizationRequest request) {
    UriComponentsBuilder builder = UriComponentsBuilder
        .fromUriString(request.getAuthorizationUri())
        .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, "code")
        .queryParam(OAuth2ParameterNames.CLIENT_ID, request.getClientId())
        .queryParam(OAuth2ParameterNames.SCOPE, String.join(" ", request.getScopes()))
        .queryParam(OAuth2ParameterNames.STATE, request.getState())
        .queryParam(OAuth2ParameterNames.REDIRECT_URI, request.getRedirectUri());

    // Convert additional parameters to MultiValueMap
    if (request.getAdditionalParameters() != null && !request.getAdditionalParameters().isEmpty()) {
      MultiValueMap<String, String> additionalParams = new LinkedMultiValueMap<>();
      request.getAdditionalParameters().forEach((key, value) -> {
        if (value != null) {
          additionalParams.add(key, value.toString());
        }
      });
      builder.queryParams(additionalParams);
    }

    return builder.build().toUriString();
  }

  /**
   * Get return URL from state
   */
  public String getReturnUrl(@NonNull String state) {
    try {
      String stateDataJson = redisTemplate.opsForValue().get(OAUTH_STATE_PREFIX + state);
      if (stateDataJson != null) {
        Map<String, Object> stateData = objectMapper.readValue(stateDataJson, Map.class);
        String returnTo = (String) stateData.get(STATE_FIELD_RETURN_TO);
        return returnTo != null && isValidReturnPath(returnTo) ? returnTo : DEFAULT_RETURN_PATH;
      }
    } catch (Exception e) {
      log.error("Failed to retrieve return URL for state: {}", state, e);
    }
    return DEFAULT_RETURN_PATH;
  }

  /**
   * Retrieves the Identity Provider associated with a given state parameter
   */
  public IdpProvider getProviderFromState(String state) {
    log.debug("Retrieving provider for state: {}", state);

    if (state == null || state.trim().isEmpty()) {
      throw new OAuth2Exception("State parameter is required");
    }

    String stateKey = OAUTH_STATE_PREFIX + state;
    String stateDataJson = redisTemplate.opsForValue().get(stateKey);

    if (stateDataJson == null) {
      log.error("State not found in cache: {}", state);
      throw new OAuth2Exception("Invalid or expired state");
    }

    try {
      Map<String, Object> stateData = objectMapper.readValue(stateDataJson, Map.class);
      String providerName = (String) stateData.get(STATE_FIELD_PROVIDER);

      if (providerName == null || providerName.isEmpty()) {
        log.error("Provider not found in state data for state: {}", state);
        throw new OAuth2Exception("Invalid state data: missing provider");
      }

      IdpProvider provider = IdpProvider.valueOf(providerName);
      log.debug("Retrieved provider {} for state: {}", provider, state);
      return provider;

    } catch (IllegalArgumentException e) {
      log.error("Invalid provider name in state data", e);
      throw new OAuth2Exception("Invalid provider in state data", e);
    } catch (JsonProcessingException e) {
      log.error("Failed to parse state data for state: {}", state, e);
      throw new OAuth2Exception("Invalid state data format", e);
    }
  }

  /**
   * Clean up expired state data - runs every hour
   */
  @Scheduled(fixedDelay = CLEANUP_INTERVAL_HOURS, timeUnit = TimeUnit.HOURS)
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

  // Private helper methods

  private String validateAndNormalizeReturnPath(String returnTo) {
    if (!isValidReturnPath(returnTo)) {
      log.warn("Invalid return path requested: {}, using default", returnTo);
      return DEFAULT_RETURN_PATH;
    }
    return returnTo;
  }

  private void storeStateData(String state, CodeVerifier codeVerifier, String nonce,
                              String returnPath, IdpProvider provider,
                              Long maxAge, String acrValues) {
    Map<String, Object> stateDataMap = new HashMap<>();
    stateDataMap.put(STATE_FIELD_CODE_VERIFIER, codeVerifier.getValue());
    stateDataMap.put(STATE_FIELD_NONCE, nonce);
    stateDataMap.put(STATE_FIELD_RETURN_TO, returnPath);
    stateDataMap.put(STATE_FIELD_PROVIDER, provider.name());
    stateDataMap.put(STATE_FIELD_CREATED_AT, System.currentTimeMillis());
    stateDataMap.put(STATE_FIELD_MAX_AGE, maxAge);
    stateDataMap.put(STATE_FIELD_ACR_VALUES, acrValues != null ? acrValues : DEFAULT_ACR_VALUES);

    try {
      String stateData = objectMapper.writeValueAsString(stateDataMap);
      redisTemplate.opsForValue().set(OAUTH_STATE_PREFIX + state, stateData, STATE_TTL);
      log.debug("Stored OAuth state for provider {} with state: {}", provider, state);
    } catch (JsonProcessingException e) {
      throw new OAuth2Exception("Failed to store state data", e);
    }
  }

  private OAuth2AuthorizationRequest buildAuthorizationRequest(
      IdpProvider provider, String state, CodeChallenge codeChallenge,
      String nonce, String prompt, Long maxAge, String loginHint, String acrValues) {

    String clientId = getClientId(provider);
    String authorizationUri = getAuthorizationUri(provider);
    String redirectUri = properties.frontend().url() + DEFAULT_REDIRECT_PATH;

    var requestBuilder = OAuth2AuthorizationRequest.authorizationCode()
        .clientId(clientId)
        .authorizationUri(authorizationUri)
        .redirectUri(redirectUri)
        .scopes(DEFAULT_SCOPES)
        .state(state);

    // Add PKCE and OIDC parameters
    Map<String, Object> additionalParams = new HashMap<>();
    additionalParams.put(PARAM_NONCE, nonce);
    additionalParams.put(PkceParameterNames.CODE_CHALLENGE, codeChallenge.getValue());
    additionalParams.put(PkceParameterNames.CODE_CHALLENGE_METHOD, CodeChallengeMethod.S256.getValue());
    additionalParams.put(PARAM_RESPONSE_MODE, DEFAULT_RESPONSE_MODE);

    // Optional OIDC parameters
    if (prompt != null && !prompt.isEmpty()) {
      additionalParams.put(PARAM_PROMPT, prompt);
    }
    if (maxAge != null) {
      additionalParams.put(PARAM_MAX_AGE, maxAge.toString());
    }
    if (loginHint != null && !loginHint.isEmpty()) {
      additionalParams.put(PARAM_LOGIN_HINT, loginHint);
    }
    if (acrValues != null && !acrValues.isEmpty()) {
      additionalParams.put(PARAM_ACR_VALUES, acrValues);
    }

    requestBuilder.additionalParameters(additionalParams);
    return requestBuilder.build();
  }

  private void preventCodeReplay(String code) {
    String codeHash = hashCode(code);
    String codeUsedKey = OAUTH_CODE_USED_PREFIX + codeHash;

    Boolean wasSet = redisTemplate.opsForValue().setIfAbsent(codeUsedKey, "1", CODE_USED_TTL);
    if (Boolean.FALSE.equals(wasSet)) {
      log.error("Authorization code replay attempt detected for code hash: {}", codeHash);
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_INVALID_GRANT, "Authorization code already used", null));
    }
  }

  private Map<String, Object> retrieveAndValidateState(String state) {
    String stateDataJson = redisTemplate.opsForValue().getAndDelete(OAUTH_STATE_PREFIX + state);
    if (stateDataJson == null) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_INVALID_GRANT, "Invalid or expired state", null));
    }

    Map<String, Object> stateData;
    try {
      stateData = objectMapper.readValue(stateDataJson, Map.class);
    } catch (JsonProcessingException e) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_INVALID_GRANT, "Invalid state data", null));
    }

    // Validate state age
    long createdAt = ((Number) stateData.get(STATE_FIELD_CREATED_AT)).longValue();
    if (System.currentTimeMillis() - createdAt > STATE_TTL.toMillis()) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_INVALID_GRANT, "State expired", null));
    }

    // Validate code verifier presence
    String codeVerifier = (String) stateData.get(STATE_FIELD_CODE_VERIFIER);
    if (codeVerifier == null || codeVerifier.isEmpty()) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_INVALID_GRANT, "Invalid PKCE verification", null));
    }

    return stateData;
  }

  private Map<String, Object> retrieveStateData(String state) {
    String stateDataJson = redisTemplate.opsForValue().get(OAUTH_STATE_PREFIX + state);
    if (stateDataJson == null) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_INVALID_REQUEST, "Invalid state", null));
    }

    try {
      return objectMapper.readValue(stateDataJson, Map.class);
    } catch (JsonProcessingException e) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_INVALID_REQUEST, "Invalid state data", null));
    }
  }

  private OIDCTokenResponse performTokenExchange(String code, String codeVerifier,
                                                 IdpProvider provider) throws URISyntaxException, IOException {
    // Create token request components
    AuthorizationCode authCode = new AuthorizationCode(code);
    URI redirectUri = new URI(properties.frontend().url() + DEFAULT_REDIRECT_PATH);
    CodeVerifier verifier = new CodeVerifier(codeVerifier);

    AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant(authCode, redirectUri, verifier);

    ClientID clientID = new ClientID(getClientId(provider));
    Secret clientSecret = new Secret(getClientSecret(provider));
    ClientSecretBasic clientAuth = new ClientSecretBasic(clientID, clientSecret);

    URI tokenEndpoint = new URI(getTokenUri(provider));
    TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, codeGrant);

    // Send token request
    HTTPResponse httpResponse = tokenRequest.toHTTPRequest().send();
    TokenResponse tokenResponse = null;
    try {
      tokenResponse = OIDCTokenResponseParser.parse(httpResponse);
    } catch (ParseException e) {
      throw new OAuth2Exception(e.getMessage());
    }

    if (!tokenResponse.indicatesSuccess()) {
      handleTokenErrorResponse(tokenResponse);
    }

    return (OIDCTokenResponse) tokenResponse;
  }

  private void storeTokensInState(String state, Map<String, Object> stateData,
                                  OIDCTokenResponse tokenResponse) {
    stateData.put(STATE_FIELD_ID_TOKEN, tokenResponse.getOIDCTokens().getIDToken().serialize());

    if (tokenResponse.getOIDCTokens().getAccessToken() != null) {
      stateData.put(STATE_FIELD_ACCESS_TOKEN, tokenResponse.getOIDCTokens().getAccessToken().getValue());
    }

    if (tokenResponse.getOIDCTokens().getRefreshToken() != null) {
      stateData.put(STATE_FIELD_REFRESH_TOKEN, tokenResponse.getOIDCTokens().getRefreshToken().getValue());
    }

    try {
      String updatedStateJson = objectMapper.writeValueAsString(stateData);
      redisTemplate.opsForValue().set(OAUTH_STATE_PREFIX + state, updatedStateJson, TEMP_STATE_TTL);
    } catch (JsonProcessingException e) {
      log.error("Failed to update state with tokens", e);
      // Non-critical error - continue processing
    }
  }

  private void validateJwtClaims(Jwt jwt, IdpProvider provider, String expectedNonce,
                                 Long requestedMaxAge, String requestedAcrValues) {
    // Validate audience
    List<String> audiences = jwt.getAudience();
    String expectedClientId = getClientId(provider);

    if (audiences == null || !audiences.contains(expectedClientId)) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_INVALID_TOKEN, "Invalid audience", null));
    }

    // Multiple audiences check - verify azp
    if (audiences.size() > 1) {
      String azp = jwt.getClaimAsString(CLAIM_AZP);
      if (!expectedClientId.equals(azp)) {
        throw new OAuth2AuthenticationException(
            new OAuth2Error(ERROR_INVALID_TOKEN, "Invalid authorized party", null));
      }
    }

    // Nonce validation
    String tokenNonce = jwt.getClaimAsString(CLAIM_NONCE);
    if (!expectedNonce.equals(tokenNonce)) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_INVALID_TOKEN, "Invalid nonce", null));
    }

    // Validate auth_time if present
    Long authTime = jwt.getClaim(CLAIM_AUTH_TIME);
    if (authTime != null) {
      validateAuthTime(authTime, requestedMaxAge);
    }

    // ACR validation (if requested)
    if (requestedAcrValues != null && !requestedAcrValues.isEmpty()) {
      validateAcr(jwt.getClaimAsString(CLAIM_ACR), requestedAcrValues);
    }

    // Additional security validations
    validateAdditionalClaims(jwt);
  }

  private void validateAuthTime(Long authTime, Long requestedMaxAge) {
    long currentTime = System.currentTimeMillis() / 1000;
    long timeSinceAuth = currentTime - authTime;

    // Check requested max_age
    if (requestedMaxAge != null && timeSinceAuth > requestedMaxAge) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_INVALID_TOKEN, "Authentication too old, max_age exceeded", null));
    }

    // Check against default maximum
    if (timeSinceAuth > DEFAULT_MAX_AUTHENTICATION_AGE_SECONDS) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_INVALID_TOKEN, "Authentication too old", null));
    }
  }

  private void validateAcr(String acr, String requestedAcrValues) {
    List<String> requestedAcrs = Arrays.asList(requestedAcrValues.split(" "));
    if (acr == null || !requestedAcrs.contains(acr)) {
      log.warn("ACR mismatch. Requested: {}, Received: {}", requestedAcrValues, acr);
      // Note: This is a warning, not a failure, as per OIDC spec
    }
  }

  private void validateAdditionalClaims(Jwt jwt) {
    // Check for required claims
    if (jwt.getSubject() == null || jwt.getSubject().isEmpty()) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_INVALID_TOKEN, "Missing subject claim", null));
    }

    // Validate issued at time
    Instant issuedAt = jwt.getIssuedAt();
    if (issuedAt != null && issuedAt.isAfter(Instant.now().plusSeconds(60))) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(ERROR_INVALID_TOKEN, "Token issued in the future", null));
    }
  }

  private UserPrincipal extractUserPrincipal(Jwt jwt) {
    int sessionTimeoutSeconds = properties.security().session().slidingWindowMinutes() * 60;

    return new UserPrincipal(
        jwt.getSubject(),
        jwt.getClaimAsString(CLAIM_PREFERRED_USERNAME),
        jwt.getClaimAsString(CLAIM_EMAIL),
        jwt.getClaimAsString(CLAIM_GIVEN_NAME),
        jwt.getClaimAsString(CLAIM_FAMILY_NAME),
        System.currentTimeMillis(),
        (long) sessionTimeoutSeconds
    );
  }

  private void handleTokenErrorResponse(TokenResponse errorResponse) {
    com.nimbusds.oauth2.sdk.ErrorObject error = errorResponse.toErrorResponse().getErrorObject();
    String errorCode = error.getCode();
    String errorDescription = error.getDescription();

    log.error("Token error response: {} - {}", errorCode, errorDescription);

    // Map to appropriate OAuth2 error
    String mappedErrorCode = ERROR_INVALID_GRANT.equals(errorCode) ? ERROR_INVALID_GRANT : errorCode;

    throw new OAuth2AuthenticationException(
        new OAuth2Error(mappedErrorCode, errorDescription,
                        error.getURI() != null ? error.getURI().toString() : null));
  }

  // Provider-specific configuration methods

  private String getClientId(IdpProvider provider) {
    return switch (provider) {
      case PING_IDENTITY -> properties.auth().ping().clientId();
      case MICROSOFT_ENTRA -> properties.auth().entra().clientId();
    };
  }

  private String getAuthorizationUri(IdpProvider provider) {
    return switch (provider) {
      case PING_IDENTITY -> properties.auth().ping().authorizationUri();
      case MICROSOFT_ENTRA -> properties.auth().entra().authority() + ENTRA_AUTHORIZE_PATH;
    };
  }

  private String getTokenUri(IdpProvider provider) {
    return switch (provider) {
      case PING_IDENTITY -> properties.auth().ping().tokenUri();
      case MICROSOFT_ENTRA -> properties.auth().entra().authority() + ENTRA_TOKEN_PATH;
    };
  }

  private String getClientSecret(IdpProvider provider) {
    return switch (provider) {
      case PING_IDENTITY -> keyVaultClient.getSecret(PING_CLIENT_SECRET_NAME);
      case MICROSOFT_ENTRA -> keyVaultClient.getSecret(ENTRA_CLIENT_SECRET_NAME);
    };
  }

  private boolean isValidReturnPath(String path) {
    return properties.auth().allowedReturnPaths().contains(path);
  }

  private String hashCode(String code) {
    try {
      MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
      byte[] hash = digest.digest(code.getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(hash);
    } catch (NoSuchAlgorithmException e) {
      throw new OAuth2Exception("Failed to hash code", e);
    }
  }
}
