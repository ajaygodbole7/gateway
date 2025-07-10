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
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * REST controller for OAuth2 authentication endpoints.
 * Handles login flow, callbacks, and session management.
 */
@RestController
@Slf4j
@RequiredArgsConstructor
public class AuthController implements AuthAPI {

  private static final String SESSION_COOKIE_NAME = "GATEWAY_SESSION";
  private static final String DEFAULT_RETURN_PATH = "/dashboard";
  private static final String PROVIDER_HEADER = "X-Auth-Provider";

  private final OAuth2Service oauth2Service;
  private final SessionService sessionService;
  private final ApplicationProperties properties;
  private final RedisTemplate<String, String> redisTemplate;

  /**
   * Initiate OAuth2 login flow.
   * Generates PKCE challenge and redirects to IdP.
   */
  @Override
  public ResponseEntity<?> login(String returnTo, HttpServletRequest request) {
    log.debug("Login request with returnTo: {}", returnTo);

    // Check if already authenticated
    String existingSessionId = extractSessionId(request);
    if (existingSessionId != null) {
      Optional<Authentication> auth = sessionService.authenticateBySessionId(existingSessionId, request);
      if (auth.isPresent()) {
        log.debug("User already authenticated, redirecting to return path");
        String redirectUrl = properties.frontend().url() + validateReturnPath(returnTo);
        return ResponseEntity.status(302)
            .location(URI.create(redirectUrl))
            .build();
      }
    }

    // Validate and sanitize return path
    String validatedReturnPath = validateReturnPath(returnTo);

    // Extract client IP for rate limiting
    String clientIp = extractClientIp(request);

    // Determine provider from header or use default
    IdpProvider provider = determineProvider(request);

    // Generate authorization URL with PKCE
    String authUrl = oauth2Service.generateAuthorizationUrl(
        provider,
        validatedReturnPath,
        clientIp
                                                           );

    log.info("Redirecting to {} for authentication", provider);

    // Return redirect response with cache control
    return ResponseEntity.status(302)
        .header(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, must-revalidate")
        .header(HttpHeaders.PRAGMA, "no-cache")
        .location(URI.create(authUrl))
        .build();
  }

  /**
   * Handle OAuth2 callback from IdP.
   * Validates state, exchanges code for tokens, and creates session.
   */
  @Override
  public ResponseEntity<?> callback(String code, String state,
                                    HttpServletRequest request,
                                    HttpServletResponse response) {
    log.debug("OAuth2 callback received with state: {}", state);

    // Validate required parameters
    if (code == null || code.trim().isEmpty()) {
      log.error("Missing authorization code in callback");
      return redirectToErrorPage("missing_code");
    }
    if (state == null || state.trim().isEmpty()) {
      log.error("Missing state parameter in callback");
      return redirectToErrorPage("missing_state");
    }

    try {
      // Extract client IP for validation
      String clientIp = extractClientIp(request);

      // Process callback (validates state, exchanges code, validates nonce)
      OAuth2Service.CallbackResult result = oauth2Service.processCallback(code, state, clientIp);

      // Create authenticated session
      String sessionId = sessionService.createAuthenticatedSession(
          result.provider(),
          result.userPrincipal(),
          result.idToken(),
          request
                                                                  );

      // Set secure session cookie
      CookieUtil.setSecureSessionCookie(response, SESSION_COOKIE_NAME, sessionId,
                                        properties.security().session().slidingWindowMinutes() * 60);

      log.info("User {} authenticated successfully via {}",
               result.userPrincipal().userId(), result.provider());

      // Redirect to frontend with return path
      String redirectUrl = properties.frontend().url() + result.returnTo();
      return ResponseEntity.status(302)
          .header(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, must-revalidate")
          .location(URI.create(redirectUrl))
          .build();

    } catch (OAuth2Exception e) {
      log.error("OAuth2 callback processing failed: {}", e.getMessage());
      return redirectToErrorPage("auth_failed");
    } catch (Exception e) {
      log.error("Unexpected error during callback processing", e);
      return redirectToErrorPage("internal_error");
    }
  }

  /**
   * Logout endpoint - invalidates session and clears cookie.
   */
  @Override
  public ResponseEntity<?> logout(String sessionId, HttpServletResponse response) {
    log.debug("Logout request");

    // Get session ID from parameter or cookie
    String actualSessionId = sessionId;
    if (actualSessionId == null || actualSessionId.trim().isEmpty()) {
      // Since we don't have request here, we'll rely on the passed sessionId
      log.debug("No session ID provided for logout");
    }

    if (actualSessionId != null) {
      // Invalidate session in Redis
      sessionService.invalidateSession(actualSessionId);
      log.info("Session invalidated: {}", actualSessionId.substring(0, 8) + "...");
    }

    // Clear session cookie
    CookieUtil.clearSessionCookie(response, SESSION_COOKIE_NAME);

    return ResponseEntity.ok(Map.of(
        "message", "Logged out successfully",
        "redirectUrl", properties.frontend().url() + "/login",
        "timestamp", System.currentTimeMillis()
                                   ));
  }

  /**
   * Refresh session TTL.
   * Manually refreshes the session TTL in Redis since SessionService doesn't have this method.
   */
  @Override
  public ResponseEntity<?> refresh(String sessionId, HttpServletRequest request) {
    log.debug("Session refresh request");

    // Get session ID from parameter or cookie
    String actualSessionId = sessionId;
    if (actualSessionId == null || actualSessionId.trim().isEmpty()) {
      actualSessionId = extractSessionId(request);
    }

    if (actualSessionId == null) {
      throw new OAuth2Exception("No session provided");
    }

    // Check if session exists by trying to authenticate
    Optional<Authentication> auth = sessionService.authenticateBySessionId(actualSessionId, request);
    if (auth.isEmpty()) {
      throw new OAuth2Exception("Session not found or expired");
    }

    // Manually refresh the session TTL in Redis
    String sessionKey = SessionService.SESSION_KEY_PREFIX + actualSessionId;
    int slidingWindowMinutes = properties.security().session().slidingWindowMinutes();
    Boolean refreshed = redisTemplate.expire(sessionKey, slidingWindowMinutes, TimeUnit.MINUTES);

    if (!Boolean.TRUE.equals(refreshed)) {
      log.warn("Failed to refresh session: {}", actualSessionId.substring(0, 8) + "...");
      throw new OAuth2Exception("Session refresh failed");
    }

    log.debug("Session refreshed successfully");
    return ResponseEntity.ok(Map.of(
        "message", "Session refreshed successfully",
        "refreshed", true,
        "timestamp", System.currentTimeMillis()
                                   ));
  }

  /**
   * Check authentication status.
   * Uses authenticateBySessionId to check validity.
   */
  @Override
  public ResponseEntity<Map<String, Object>> status(String sessionId) {
    log.debug("Authentication status check");

    boolean isAuthenticated = false;

    // Note: We can't use authenticateBySessionId here without HttpServletRequest
    // So we'll check if the session key exists in Redis
    if (sessionId != null && !sessionId.trim().isEmpty()) {
      String sessionKey = SessionService.SESSION_KEY_PREFIX + sessionId;
      isAuthenticated = Boolean.TRUE.equals(redisTemplate.hasKey(sessionKey));
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

    // Remove any protocol/host if present (security measure)
    String path = returnTo.replaceAll("^https?://[^/]+", "");

    // Ensure it starts with /
    if (!path.startsWith("/")) {
      path = "/" + path;
    }

    // Validate against allowed paths
    if (properties.auth().allowedReturnPaths().contains(path)) {
      return path;
    }

    log.warn("Invalid return path requested: {}, using default", returnTo);
    return DEFAULT_RETURN_PATH;
  }

  private String extractClientIp(HttpServletRequest request) {
    // Check forwarded headers first (for proxies/load balancers)
    String xForwardedFor = request.getHeader("X-Forwarded-For");
    if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
      // Take the first IP if multiple are present
      return xForwardedFor.split(",")[0].trim();
    }

    String xRealIp = request.getHeader("X-Real-IP");
    if (xRealIp != null && !xRealIp.isEmpty()) {
      return xRealIp;
    }

    // Fallback to remote address
    return request.getRemoteAddr();
  }

  private String extractSessionId(HttpServletRequest request) {
    return CookieUtil.getCookie(request, SESSION_COOKIE_NAME)
        .map(Cookie::getValue)
        .filter(id -> !id.trim().isEmpty())
        .orElse(null);
  }

  private IdpProvider determineProvider(HttpServletRequest request) {
    // Check for provider header
    String providerHeader = request.getHeader(PROVIDER_HEADER);
    if (providerHeader != null) {
      try {
        return IdpProvider.valueOf(providerHeader.toUpperCase());
      } catch (IllegalArgumentException e) {
        log.warn("Invalid provider header: {}", providerHeader);
      }
    }

    // Default to PING_IDENTITY
    // In production, this could be based on domain, user preference, etc.
    return IdpProvider.PING_IDENTITY;
  }

  private ResponseEntity<?> redirectToErrorPage(String error) {
    String errorUrl = properties.frontend().url() + "/auth/error?code=" + error;
    return ResponseEntity.status(302)
        .location(URI.create(errorUrl))
        .build();
  }
}
