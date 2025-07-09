package com.example.gateway.web.rest.controller;

import com.example.gateway.domain.entity.IdpProvider;
import com.example.gateway.exception.OAuth2Exception;
import com.example.gateway.properties.ApplicationProperties;
import com.example.gateway.service.OAuth2Service;
import com.example.gateway.service.SessionService;
import com.example.gateway.util.CookieUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.Map;
import java.util.Optional;

/**
 * REST controller for OAuth2 authentication endpoints.
 * Focuses on HTTP concerns - parsing requests and returning responses.
 */
@RestController
@Slf4j
@RequiredArgsConstructor
public class AuthController implements AuthAPI {

  private static final String SESSION_COOKIE_NAME = "GATEWAY_SESSION";
  private static final String DEFAULT_RETURN_PATH = "/dashboard";

  private final OAuth2Service oauth2Service;
  private final SessionService sessionService;
  private final ApplicationProperties properties;

  @Override
  public ResponseEntity<?> login(String returnTo, HttpServletRequest request) {
    log.debug("Login request with returnTo: {}", returnTo);

    // Validate and sanitize return path
    String validatedReturnPath = validateReturnPath(returnTo);

    // Extract client IP for rate limiting
    String clientIp = extractClientIp(request);

    // TODO: Add logic to determine provider (for now default to PING)
    IdpProvider provider = IdpProvider.PING_IDENTITY;

    // Generate authorization URL
    String authUrl = oauth2Service.generateAuthorizationUrl(
        provider,
        validatedReturnPath,
        clientIp
                                                           );

    log.info("Redirecting to IdP for authentication");

    // Return redirect response
    return ResponseEntity.status(302)
        .location(URI.create(authUrl))
        .build();
  }

  @Override
  public ResponseEntity<?> callback(String code, String state,
                                    HttpServletRequest request,
                                    HttpServletResponse response) {
    log.debug("OAuth2 callback received");

    // Validate required parameters
    if (code == null || code.trim().isEmpty()) {
      throw new OAuth2Exception("Missing authorization code");
    }
    if (state == null || state.trim().isEmpty()) {
      throw new OAuth2Exception("Missing state parameter");
    }

    // Extract client IP
    String clientIp = extractClientIp(request);

    // Process callback
    OAuth2Service.CallbackResult result = oauth2Service.processCallback(code, state, clientIp);

    // Create session
    String sessionId = sessionService.createAuthenticatedSession(
        result.provider(),
        result.userPrincipal(),
        result.idToken(),
        request
                                                                );

    // Set secure session cookie
    CookieUtil.setSecureSessionCookie(response, sessionId);

    log.info("User {} authenticated successfully", result.userPrincipal().userId());

    // Redirect to frontend with return path
    String redirectUrl = properties.frontend().url() + result.returnTo();
    return ResponseEntity.status(302)
        .location(URI.create(redirectUrl))
        .build();
  }

  @Override
  public ResponseEntity<?> logout(String sessionId, HttpServletResponse response) {
    log.debug("Logout request");

    // Get session ID from cookie if not provided
    if (sessionId == null || sessionId.trim().isEmpty()) {
      log.debug("No session ID provided for logout");
    } else {
      // Invalidate session
      sessionService.invalidateSession(sessionId);
      log.info("Session invalidated");
    }

    // Clear session cookie
    CookieUtil.clearSessionCookie(response);

    return ResponseEntity.ok(Map.of(
        "message", "Logged out successfully",
        "timestamp", System.currentTimeMillis()
                                   ));
  }

  @Override
  public ResponseEntity<?> refresh(String sessionId, HttpServletRequest request) {
    log.debug("Session refresh request");

    // Get session ID from cookie if not provided
    String actualSessionId = sessionId;
    if (actualSessionId == null || actualSessionId.trim().isEmpty()) {
      actualSessionId = getSessionIdFromCookie(request).orElse(null);
    }

    if (actualSessionId == null) {
      throw new OAuth2Exception("No session provided");
    }

    // Refresh session
    boolean refreshed = sessionService.refreshSession(actualSessionId);
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
    log.debug("Authentication status check");

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

    // Ensure it starts with /
    if (!path.startsWith("/")) {
      path = "/" + path;
    }

    // Check against allowed paths
    if (properties.auth().allowedReturnPaths().contains(path)) {
      return path;
    }

    log.warn("Invalid return path requested: {}, using default", returnTo);
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

  private Optional<String> getSessionIdFromCookie(HttpServletRequest request) {
    return CookieUtil.getCookie(request, SESSION_COOKIE_NAME)
        .map(Cookie::getValue);
  }
}
