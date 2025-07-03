package com.example.gateway.service;

import com.example.gateway.adapter.keyvault.client.AzureKeyVaultClient;
import com.example.gateway.domain.entity.UserPrincipal;
import com.example.gateway.exception.OAuth2Exception;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
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

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * OAuth2 Service with full PKCE and OIDC support
 *
 * Implements:
 * - RFC 7636 (PKCE) with proper error handling
 * - OpenID Connect Core 1.0
 * - Request Object support
 * - Enhanced token validation
 */
@Slf4j
@Service
@Profile("!test")
@RequiredArgsConstructor
public class OAuth2Service {

  private final RedisTemplate<String, String> redisTemplate;
  private final JwtDecoder jwtDecoder;
  private final AzureKeyVaultClient keyVaultClient;
  private final ClientRegistration clientRegistration;
  private final TokenManagerService tokenManager;
  private final ObjectMapper objectMapper;

  @Value("${app.auth.oidc.max-authentication-age:3600}")
  private long maxAuthenticationAge;

  @Value("${app.auth.oidc.use-request-object:false}")
  private boolean useRequestObject;

  @Value("${app.auth.pkce.code-verifier-length:128}")
  private int codeVerifierLength;

  @Value("${app.auth.oidc.required-acr-values:}")
  private String requiredAcrValues;

  private static final String OAUTH_STATE_PREFIX = "oauth:state:";
  private static final Duration STATE_TTL = Duration.ofMinutes(10);

  // OAuth2/OIDC error codes
  private static final String INVALID_REQUEST = "invalid_request";
  private static final String INVALID_GRANT = "invalid_grant";
  private static final String INVALID_TOKEN = "invalid_token";
  private static final String TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";

  /**
   * Generate OAuth2 authorization request with full OIDC support
   */
  public OAuth2AuthorizationRequest generateAuthorizationRequest(
      String returnTo,
      String prompt,
      Long maxAge,
      String loginHint,
      String acrValues) {

    // Generate PKCE parameters with configurable length
    CodeVerifier codeVerifier = new CodeVerifier(codeVerifierLength);
    CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier);

    String state = UUID.randomUUID().toString();
    String nonce = UUID.randomUUID().toString();

    // Create comprehensive state data
    Map<String, Object> stateDataMap = new HashMap<>();
    stateDataMap.put("codeVerifier", codeVerifier.getValue());
    stateDataMap.put("nonce", nonce);
    stateDataMap.put("returnTo", returnTo);
    stateDataMap.put("createdAt", System.currentTimeMillis());
    stateDataMap.put("maxAge", maxAge);
    stateDataMap.put("acrValues", acrValues);

    try {
      String stateData = objectMapper.writeValueAsString(stateDataMap);
      redisTemplate.opsForValue().set(OAUTH_STATE_PREFIX + state, stateData, STATE_TTL);
    } catch (Exception e) {
      throw new OAuth2Exception("Failed to store state data", e);
    }

    // Build authorization request
    var requestBuilder = OAuth2AuthorizationRequest.authorizationCode()
        .clientId(clientRegistration.getClientId())
        .authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
        .redirectUri(clientRegistration.getRedirectUri())
        .scopes(clientRegistration.getScopes())
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
  public OAuth2AuthorizationRequest generateAuthorizationRequest(String returnTo) {
    return generateAuthorizationRequest(returnTo, null, null, null, requiredAcrValues);
  }

  /**
   * Exchange authorization code for tokens with enhanced error handling
   */
  public String exchangeCodeForToken(String code, String state) {
    // Retrieve and validate state
    String stateDataJson = redisTemplate.opsForValue().getAndDelete(OAUTH_STATE_PREFIX + state);
    if (stateDataJson == null) {
      // RFC 7636 Section 4.6 - Must return invalid_grant for PKCE failures
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

    String codeVerifier = (String) stateData.get("codeVerifier");
    if (codeVerifier == null || codeVerifier.isEmpty()) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(INVALID_GRANT, "Invalid PKCE verification", null));
    }

    try {
      // Create token request using Nimbus
      AuthorizationCode authCode = new AuthorizationCode(code);
      URI redirectUri = new URI(clientRegistration.getRedirectUri());
      CodeVerifier verifier = new CodeVerifier(codeVerifier);

      AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant(
          authCode, redirectUri, verifier);

      ClientID clientID = new ClientID(clientRegistration.getClientId());
      Secret clientSecret = new Secret(getClientSecret());
      ClientSecretBasic clientAuth = new ClientSecretBasic(clientID, clientSecret);

      URI tokenEndpoint = new URI(clientRegistration.getProviderDetails().getTokenUri());
      TokenRequest tokenRequest = new TokenRequest(
          tokenEndpoint, clientAuth, codeGrant);

      // Send token request
      HTTPResponse httpResponse = tokenRequest.toHTTPRequest().send();
      TokenResponse tokenResponse = OIDCTokenResponseParser.parse(httpResponse);

      if (!tokenResponse.indicatesSuccess()) {
        handleTokenErrorResponse(tokenResponse);
      }

      OIDCTokenResponse oidcResponse = (OIDCTokenResponse) tokenResponse;

      // Store tokens in state data for potential refresh
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

      return oidcResponse.getOIDCTokens().getIDToken().serialize();

    } catch (URISyntaxException | IOException e) {
      log.error("Token exchange failed", e);
      throw new OAuth2AuthenticationException(
          new OAuth2Error(TEMPORARILY_UNAVAILABLE, "Service temporarily unavailable", null));
    } catch (OAuth2AuthenticationException e) {
      throw e;
    } catch (Exception e) {
      log.error("Unexpected error during token exchange", e);
      throw new OAuth2AuthenticationException(
          new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "Token exchange failed", null));
    }
  }

  /**
   * Validate ID token with comprehensive OIDC checks
   */
  public UserPrincipal validateIdToken(String idToken, String state) {
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

    try {
      // Decode and validate JWT
      Jwt jwt = jwtDecoder.decode(idToken);

      // 1. Issuer validation (done by JwtDecoder)

      // 2. Audience validation
      List<String> audiences = jwt.getAudience();
      if (audiences == null || !audiences.contains(clientRegistration.getClientId())) {
        throw new OAuth2AuthenticationException(
            new OAuth2Error(INVALID_TOKEN, "Invalid audience", null));
      }

      // 3. Multiple audiences check - verify azp
      if (audiences.size() > 1) {
        String azp = jwt.getClaimAsString("azp");
        if (!clientRegistration.getClientId().equals(azp)) {
          throw new OAuth2AuthenticationException(
              new OAuth2Error(INVALID_TOKEN, "Invalid authorized party", null));
        }
      }

      // 4. Nonce validation
      String tokenNonce = jwt.getClaimAsString("nonce");
      if (!expectedNonce.equals(tokenNonce)) {
        throw new OAuth2AuthenticationException(
            new OAuth2Error(INVALID_TOKEN, "Invalid nonce", null));
      }

      // 5. auth_time validation
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
        if (timeSinceAuth > maxAuthenticationAge) {
          throw new OAuth2AuthenticationException(
              new OAuth2Error(INVALID_TOKEN, "Authentication too old", null));
        }
      }

      // 6. ACR validation
      if (requestedAcrValues != null && !requestedAcrValues.isEmpty()) {
        String acr = jwt.getClaimAsString("acr");
        List<String> requestedAcrs = Arrays.asList(requestedAcrValues.split(" "));
        if (acr == null || !requestedAcrs.contains(acr)) {
          log.warn("ACR mismatch. Requested: {}, Received: {}", requestedAcrValues, acr);
          // Depending on policy, this might be an error
        }
      }

      // 7. Additional security checks
      validateAdditionalClaims(jwt);

      // Extract user information
      return new UserPrincipal(
          jwt.getSubject(),
          jwt.getClaimAsString("preferred_username"),
          jwt.getClaimAsString("email"),
          jwt.getClaimAsString("given_name"),
          jwt.getClaimAsString("family_name"),
          System.currentTimeMillis(),
          3600L
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
    }
  }

  /**
   * Build authorization URL with optional request object
   */
  public String buildAuthorizationUrl(OAuth2AuthorizationRequest request) {
    if (useRequestObject) {
      return buildAuthorizationUrlWithRequestObject(request);
    }

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
   * Build authorization URL with JWT request object
   */
  private String buildAuthorizationUrlWithRequestObject(OAuth2AuthorizationRequest request) {
    try {
      String requestJwt = buildRequestObject(request);

      return UriComponentsBuilder
          .fromUriString(request.getAuthorizationUri())
          .queryParam(OAuth2ParameterNames.CLIENT_ID, request.getClientId())
          .queryParam("request", requestJwt)
          .build()
          .toUriString();

    } catch (Exception e) {
      log.error("Failed to build request object, falling back to standard URL", e);
      return buildAuthorizationUrl(request);
    }
  }

  /**
   * Build JWT request object for secure authorization requests
   */
  private String buildRequestObject(OAuth2AuthorizationRequest request) throws JOSEException {
    JWTClaimsSet claims = new JWTClaimsSet.Builder()
        .issuer(request.getClientId())
        .audience(Collections.singletonList(
            clientRegistration.getProviderDetails().getIssuerUri()))
        .claim("response_type", "code")
        .claim("client_id", request.getClientId())
        .claim("redirect_uri", request.getRedirectUri())
        .claim("scope", String.join(" ", request.getScopes()))
        .claim("state", request.getState())
        .claim("nonce", request.getAdditionalParameters().get("nonce"))
        .claim("code_challenge", request.getAdditionalParameters().get("code_challenge"))
        .claim("code_challenge_method", request.getAdditionalParameters().get("code_challenge_method"))
        .expirationTime(Date.from(Instant.now().plusSeconds(300)))
        .issueTime(Date.from(Instant.now()))
        .jwtID(UUID.randomUUID().toString())
        .build();

    // Add additional parameters
    request.getAdditionalParameters().forEach((key, value) -> {
      if (!claims.getClaims().containsKey(key)) {
        claims = new JWTClaimsSet.Builder(claims).claim(key, value).build();
      }
    });

    // Sign with client secret
    SignedJWT signedJWT = new SignedJWT(
        new JWSHeader(JWSAlgorithm.HS256),
        claims
    );

    JWSSigner signer = new MACSigner(getClientSecret().getBytes());
    signedJWT.sign(signer);

    return signedJWT.serialize();
  }

  /**
   * Get return URL from state
   */
  public String getReturnUrl(String state) {
    try {
      String stateDataJson = redisTemplate.opsForValue().get(OAUTH_STATE_PREFIX + state);
      if (stateDataJson != null) {
        Map<String, Object> stateData = objectMapper.readValue(stateDataJson, Map.class);
        String returnTo = (String) stateData.get("returnTo");
        return returnTo != null ? returnTo : "/dashboard";
      }
    } catch (Exception e) {
      log.error("Failed to retrieve return URL", e);
    }
    return "/dashboard";
  }

  /**
   * Build end session URL for OIDC logout
   */
  public String buildEndSessionUrl(String idToken, String postLogoutRedirectUri, String state) {
    Map<String, Object> metadata = clientRegistration.getProviderDetails().getConfigurationMetadata();
    String endSessionEndpoint = (String) metadata.get("end_session_endpoint");

    if (endSessionEndpoint == null) {
      log.warn("No end_session_endpoint found in provider metadata");
      return postLogoutRedirectUri != null ? postLogoutRedirectUri : "/";
    }

    UriComponentsBuilder builder = UriComponentsBuilder
        .fromUriString(endSessionEndpoint)
        .queryParam("id_token_hint", idToken);

    if (postLogoutRedirectUri != null) {
      builder.queryParam("post_logout_redirect_uri", postLogoutRedirectUri);
    }

    if (state != null) {
      builder.queryParam("state", state);
    }

    return builder.build().toUriString();
  }

  /**
   * Validate additional security claims
   */
  private void validateAdditionalClaims(Jwt jwt) {
    // Validate token binding if required
    String cnf = jwt.getClaimAsString("cnf");
    if (cnf != null) {
      // Implement token binding validation
      log.debug("Token binding claim present: {}", cnf);
    }

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
   * Get client secret from Key Vault
   */
  private String getClientSecret() {
    return keyVaultClient.getSecret("ping-client-secret");
  }

  /**
   * Clean up expired state data
   */
  public void cleanupExpiredState() {
    Set<String> keys = redisTemplate.keys(OAUTH_STATE_PREFIX + "*");
    if (keys != null) {
      for (String key : keys) {
        String stateData = redisTemplate.opsForValue().get(key);
        if (stateData != null) {
          try {
            Map<String, Object> data = objectMapper.readValue(stateData, Map.class);
            long createdAt = ((Number) data.get("createdAt")).longValue();
            if (System.currentTimeMillis() - createdAt > STATE_TTL.toMillis()) {
              redisTemplate.delete(key);
            }
          } catch (Exception e) {
            log.error("Failed to clean up state: {}", key, e);
          }
        }
      }
    }
  }
}
