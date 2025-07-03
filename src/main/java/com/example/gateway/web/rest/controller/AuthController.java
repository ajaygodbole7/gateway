package com.example.gateway.web.rest.controller;



import com.example.gateway.domain.entity.UserPrincipal;
import com.example.gateway.security.AuthenticationFailureTracker;
import com.example.gateway.service.OAuth2Service;
import com.example.gateway.service.SessionService;
import com.example.gateway.util.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.List;
import java.util.Map;

/**
 * REST controller implementation for OAuth2 authentication.
 * Handles login flow, callbacks, and session management.
 */
@RestController
@Slf4j
@RequiredArgsConstructor
public class AuthController implements AuthAPI {

  private final OAuth2Service oauth2Service;
  private final SessionService sessionService;
  private final AuthenticationFailureTracker failureTracker;

  @Value("${app.frontend.url}")
  private String frontendUrl;

  @Value("${app.auth.allowed-return-paths}")
  private List<String> allowedReturnPaths;

  @Override
  public ResponseEntity<?> login(String returnTo, HttpServletRequest request) {
    log.debug("REST request to initiate login with returnTo: {}", returnTo);

    try {
      String validatedReturnPath = validateReturnPath(returnTo);
      String clientIp = extractClientIp(request);

      if (failureTracker.isBlocked(clientIp)) {
        log.warn("Login attempt from blocked IP: {}", maskIpAddress(clientIp));
        return ResponseEntity.status(429).body(Map.of("error", "Too many failed attempts"));
      }

      OAuth2AuthorizationRequest authRequest =
          oauth2Service.generateAuthorizationRequest(validatedReturnPath);

      String authUrl = oauth2Service.buildAuthorizationUrl(authRequest);

      log.info("Initiating OAuth2 flow with state: {}", authRequest.getState());

      return ResponseEntity.status(302)
          .location(URI.create(authUrl))
          .build();

    } catch (Exception e) {
      log.error("Failed to initiate OAuth2 flow", e);
      return redirectToLoginWithError("authentication_error");
    }
  }

  @Override
  public ResponseEntity<?> callback(String code, String state,
                                    HttpServletRequest request, HttpServletResponse response) {
    log.debug("REST request to handle OAuth2 callback");

    String clientIp = extractClientIp(request);

    try {
      if (failureTracker.isBlocked(clientIp)) {
        log.warn("Callback attempt from blocked IP: {}", maskIpAddress(clientIp));
        return ResponseEntity.status(429).body(Map.of("error", "Too many failed attempts"));
      }

      String idToken = oauth2Service.exchangeCodeForToken(code, state);
      UserPrincipal userPrincipal = oauth2Service.validateIdToken(idToken, state);

      String sessionId = sessionService.createAuthenticatedSession(userPrincipal, idToken, request);
      CookieUtil.setSecureSessionCookie(response, sessionId);

      failureTracker.clearFailures(clientIp);

      log.info("User authenticated successfully: {}", userPrincipal.username());

      String returnUrl = oauth2Service.getReturnUrl(state);
      return ResponseEntity.status(302)
          .location(URI.create(frontendUrl + returnUrl))
          .build();

    } catch (Exception e) {
      log.error("OAuth2 callback failed", e);
      failureTracker.recordFailure(clientIp);
      return redirectToLoginWithError("authentication_error");
    }
  }

  @Override
  public ResponseEntity<?> logout(String sessionId, HttpServletResponse response) {
    log.debug("REST request to logout user");

    if (sessionId != null) {
      sessionService.invalidateSession(sessionId);
      log.info("Session invalidated");
    }

    CookieUtil.clearSessionCookie(response);
    return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
  }

  @Override
  public ResponseEntity<?> refresh(String sessionId, HttpServletRequest request) {
    log.debug("REST request to refresh session");

    if (sessionId == null) {
      return ResponseEntity.status(401).body(Map.of("error", "No session"));
    }

    try {
      boolean refreshed = sessionService.refreshSession(sessionId);
      if (refreshed) {
        return ResponseEntity.ok(Map.of("message", "Session refreshed"));
      } else {
        return ResponseEntity.status(401).body(Map.of("error", "Refresh failed"));
      }
    } catch (Exception e) {
      log.error("Session refresh failed", e);
      return ResponseEntity.status(401).body(Map.of("error", "Refresh failed"));
    }
  }

  @Override
  public ResponseEntity<Map<String, Object>> status(String sessionId) {
    log.debug("REST request to check authentication status");

    if (sessionId == null) {
      return ResponseEntity.ok(Map.of("authenticated", false));
    }

    boolean isValid = sessionService.isSessionValid(sessionId);
    return ResponseEntity.ok(Map.of("authenticated", isValid));
  }

  // Helper methods remain the same...
  private String validateReturnPath(String returnTo) {
    String path = returnTo.replaceAll("^https?://[^/]+", "");

    if (allowedReturnPaths.contains(path)) {
      return path;
    }

    log.warn("Invalid return path requested: {}, defaulting to /dashboard", returnTo);
    return "/dashboard";
  }

  private String extractClientIp(HttpServletRequest request) {
    String xForwardedFor = request.getHeader("X-Forwarded-For");
    if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
      return xForwardedFor.split(",")[0].trim();
    }

    return request.getRemoteAddr();
  }

  private String maskIpAddress(String ip) {
    if (ip == null || !ip.contains(".")) {
      return "***";
    }
    String[] parts = ip.split("\\.");
    return parts[0] + "." + parts[1] + ".***." + parts[3];
  }

  private ResponseEntity<?> redirectToLoginWithError(String error) {
    return ResponseEntity.status(302)
        .location(URI.create(frontendUrl + "/login?error=" + error))
        .build();
  }
}
