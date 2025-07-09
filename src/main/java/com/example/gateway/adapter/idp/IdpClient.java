package com.example.gateway.adapter.idp;

import com.example.gateway.domain.entity.UserPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Interface for Identity Provider clients.
 * Handles protocol-specific operations, not validation.
 */
public interface IdpClient {

  /**
   * Gets the authorization endpoint URL.
   */
  String getAuthorizationEndpoint();

  /**
   * Gets the client ID for this IdP.
   */
  String getClientId();

  /**
   * Exchanges authorization code for tokens using PKCE.
   */
  TokenResponse exchangeCodeForTokens(String code, String codeVerifier, String redirectUri);

  /**
   * Extracts user principal from a validated JWT.
   * Note: JWT is already validated, this just extracts claims.
   */
  UserPrincipal extractUserPrincipal(Jwt jwt);

  /**
   * Token response from the IdP.
   */
  record TokenResponse(
      String idToken,
      String accessToken,
      String refreshToken,
      long expiresIn
  ) {}
}
