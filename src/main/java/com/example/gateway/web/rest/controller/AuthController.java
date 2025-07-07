package com.example.gateway.web.rest.controller;

import com.example.gateway.domain.entity.IdpProvider;
import com.example.gateway.domain.entity.UserPrincipal;
import com.example.gateway.exception.OAuth2Exception;
import com.example.gateway.exception.RateLimitException;
import com.example.gateway.properties.ApplicationProperties;
import com.example.gateway.security.AuthenticationFailureTracker;
import com.example.gateway.service.OAuth2Service;
import com.example.gateway.service.SessionService;
import com.example.gateway.util.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller implementation for OAuth2 authentication.
 * Delegates error handling to GlobalErrorHandler.
 */
@RestController
@Slf4j
@RequiredArgsConstructor
public class AuthController implements AuthAPI {

  // Constants
  private static final String DEFAULT_RETURN_PATH = "/dashboard";
  private static final String LOGIN_ERROR_PATH = "/login?error=";
  private static final String IP_MASK_PATTERN = "***";
  private static final String SESSION_COOKIE_NAME = "GATEWAY_SESSION";

  private final OAuth2Service oauth2Service;
  private final SessionService sessionService;
  private final AuthenticationFailureTracker failureTracker;
  private final ApplicationProperties properties;

  @Override
  public ResponseEntity<?> login(String returnTo, HttpServletRequest request) {
    log.debug("REST request to initiate login with returnTo: {}", returnTo);

    String clientIp = extractClientIp(request);

    // Check rate limiting
    if (failureTracker.isBlocked(clientIp)) {
      log.warn("Login attempt from blocked IP: {}", maskIpAddress(clientIp));
      throw new RateLimitException("Too many failed authentication attempts");
    }

    String validatedReturnPath = validateReturnPath(returnTo);

    // Generate authorization request - let OAuth2Service handle its exceptions
    OAuth2AuthorizationRequest authRequest =
        oauth2Service.generateAuthorizationRequest(
            IdpProvider.PING_IDENTITY, // Or determine dynamically
            validatedReturnPath
                                                  );

    String authUrl = oauth2Service.buildAuthorizationUrl(authRequest);
    log.info("Initiating OAuth2 flow with state: {}", authRequest.getState());

    return ResponseEntity.status(302)
        .location(URI.create(authUrl))
        .build();
  }

  @Override
  public ResponseEntity<?> callback(String code, String state,
                                    HttpServletRequest request,
                                    HttpServletResponse response) {
    log.debug("REST request to handle OAuth2 callback");

    String clientIp = extractClientIp(request);

    // Check rate limiting
    if (failureTracker.isBlocked(clientIp)) {
      log.warn("Callback attempt from blocked IP: {}", maskIpAddress(clientIp));
      throw new RateLimitException("Too many failed authentication attempts");
    }

    // Validate required parameters
    if (code == null || code.trim().isEmpty()) {
      throw new OAuth2Exception("Missing authorization code");
    }

    if (state == null || state.trim().isEmpty()) {
      throw new OAuth2Exception("Missing state parameter");
    }

    try {
      // Exchange code for token - OAuth2Service will throw appropriate exceptions
      String idToken = oauth2Service.exchangeCodeForToken(code, state);
      UserPrincipal userPrincipal = oauth2Service.validateIdToken(idToken, state);
      IdpProvider provider = oauth2Service.getProviderFromState(state);

      // Create session
      String sessionId = sessionService.createAuthenticatedSession(
          provider,
          userPrincipal,
          idToken,
          request
                                                                  );

      // Set secure cookie
      CookieUtil.setSecureSessionCookie(response, sessionId);

      // Clear failure tracking on success
      failureTracker.clearFailures(clientIp);

      log.info("User authenticated successfully: {}", userPrincipal.username());

      // Get return URL
      String returnUrl = oauth2Service.getReturnUrl(state);
      String frontendUrl = properties.frontend().url();

      return ResponseEntity.status(302)
          .location(URI.create(frontendUrl + returnUrl))
          .build();

    } catch (Exception e) {
      // Record failure for rate limiting
      failureTracker.recordFailure(clientIp);

      // Re-throw to let GlobalErrorHandler handle it
      throw e;
    }
  }

  @Override
  public ResponseEntity<?> logout(String sessionId, HttpServletResponse response) {
    log.debug("REST request to logout user");

    // Extract session ID from cookie if not provided
    if (sessionId == null || sessionId.trim().isEmpty()) {
      log.debug("No session ID provided for logout");
    } else {
      sessionService.invalidateSession(sessionId);
      log.info("Session invalidated successfully");
    }

    CookieUtil.clearSessionCookie(response);

    return ResponseEntity.ok(Map.of(
        "message", "Logged out successfully",
        "timestamp", System.currentTimeMillis()
                                   ));
  }

  @Override
  public ResponseEntity<?> refresh(String sessionId, HttpServletRequest request) {
    log.debug("REST request to refresh session");

    if (sessionId == null || sessionId.trim().isEmpty()) {
      throw new OAuth2Exception("No session provided");
    }

    boolean refreshed = sessionService.refreshSession(sessionId);

    if (!refreshed) {
      throw new OAuth2Exception("Session refresh failed");
    }

    return ResponseEntity.ok(Map.of(
        "message", "Session refreshed successfully",
        "timestamp", System.currentTimeMillis()
                                   ));
  }

  @Override
  public ResponseEntity<Map<String, Object>> status(String sessionId) {
    log.debug("REST request to check authentication status");

    boolean isAuthenticated = false;

    if (sessionId != null && !sessionId.trim().isEmpty()) {
      isAuthenticated = sessionService.isSessionValid(sessionId);
    }

    return ResponseEntity.ok(Map.of(
        "authenticated", isAuthenticated,
        "timestamp", System.currentTimeMillis()
                                   ));
  }

  // Helper methods
  private String validateReturnPath(String returnTo) {
    if (returnTo == null || returnTo.trim().isEmpty()) {
      return DEFAULT_RETURN_PATH;
    }

    // Remove any protocol/host if present
    String path = returnTo.replaceAll("^https?://[^/]+", "");

    // Check against allowed paths
    if (properties.auth().allowedReturnPaths().contains(path)) {
      return path;
    }

    log.warn("Invalid return path requested: {}, defaulting to {}",
             returnTo, DEFAULT_RETURN_PATH);
    return DEFAULT_RETURN_PATH;
  }

  private String extractClientIp(HttpServletRequest request) {
    String xForwardedFor = request.getHeader("X-Forwarded-For");
    if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
      return xForwardedFor.split(",")[0].trim();
    }

    String xRealIp = request.getHeader("X-Real-IP");
    if (xRealIp != null && !xRealIp.isEmpty()) {
      return xRealIp;
    }

    return request.getRemoteAddr();
  }

  private String maskIpAddress(String ip) {
    if (ip == null || !ip.contains(".")) {
      return IP_MASK_PATTERN;
    }

    String[] parts = ip.split("\\.");
    if (parts.length != 4) {
      return IP_MASK_PATTERN;
    }

    return parts[0] + "." + parts[1] + "." + IP_MASK_PATTERN + "." + IP_MASK_PATTERN;
  }
}
