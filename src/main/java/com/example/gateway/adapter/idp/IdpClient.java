package com.example.gateway.adapter.idp;

import com.example.gateway.domain.entity.UserPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * An abstraction for an Identity Provider (IdP) client, defining the core
 * operations needed for an OIDC flow: exchanging an authorization code for tokens
 * and validating the resulting ID token.
 */
public interface IdpClient {

  /**
   * Gets the authorization endpoint URI for this IdP.
   * @return The authorization endpoint URL as a string.
   */
  String getAuthorizationEndpoint();

  /**
   * Gets the client ID for this IdP.
   * @return The client ID string.
   */
  String getClientId();

  /**
   * Exchanges an authorization code for a set of tokens.
   *
   * @param code The authorization code received from the IdP.
   * @param codeVerifier The PKCE code verifier for this transaction.
   * @param redirectUri The redirect URI used in the initial request.
   * @return A TokenResponse containing the ID, access, and refresh tokens.
   */
  TokenResponse exchangeCodeForTokens(String code, String codeVerifier, String redirectUri);

  /**
   * Validates the cryptographic signature and standard claims of an ID token.
   *
   * @param idToken The ID token string to validate.
   * @return A validated Jwt object.
   */
  Jwt validateIdToken(String idToken);

  /**
   * Extracts a standardized UserPrincipal from a validated JWT.
   *
   * @param jwt The validated Jwt object.
   * @return A UserPrincipal containing core user attributes.
   */
  UserPrincipal extractUserPrincipal(Jwt jwt);

  /**
   * A record to hold the results of a successful token exchange.
   */
  record TokenResponse(
      String idToken,
      String accessToken,
      String refreshToken,
      long expiresIn
  ) {}
}
