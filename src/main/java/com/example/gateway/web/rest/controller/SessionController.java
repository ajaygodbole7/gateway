package com.example.gateway.web.rest.controller;

import com.example.gateway.domain.entity.UserPrincipal;
import com.example.gateway.exception.SessionException;
import com.example.gateway.service.SessionService;
import com.example.gateway.util.CookieUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Session management REST controller.
 * Provides endpoints for React UI session checks.
 */
@RestController
@Slf4j
@RequiredArgsConstructor
public class SessionController implements SessionAPI {

  private static final String SESSION_COOKIE_NAME = "GATEWAY_SESSION";
  private final SessionService sessionService;
  private final HttpServletRequest request;

  /**
   * Lightweight session check.
   * Uses authenticateBySessionId to verify session validity.
   */
  @Override
  public ResponseEntity<Map<String, Object>> checkSession() {
    String sessionId = extractSessionId();
    boolean valid = false;

    if (sessionId != null) {
      Optional<Authentication> auth = sessionService.authenticateBySessionId(sessionId, request);
      valid = auth.isPresent();
    }

    if (log.isTraceEnabled()) {
      log.trace("Session check for ID {}: {}",
                sessionId != null ? sessionId.substring(0, 8) + "..." : "null", valid);
    }

    return ResponseEntity.ok(Map.of(
        "authenticated", valid,
        "timestamp", System.currentTimeMillis()
                                   ));
  }

  /**
   * Get current user info.
   * Extracts user information from the authenticated session.
   */
  @Override
  public ResponseEntity<Map<String, Object>> getCurrentUser() {
    String sessionId = extractSessionId();
    if (sessionId == null) {
      throw new SessionException("No session found");
    }

    Optional<Authentication> authOpt = sessionService.authenticateBySessionId(sessionId, request);

    return authOpt.map(auth -> {
      UserPrincipal principal = (UserPrincipal) auth.getPrincipal();

      Map<String, Object> userInfo = new HashMap<>();
      userInfo.put("userId", principal.userId());
      userInfo.put("username", principal.username());
      userInfo.put("email", principal.email());
      userInfo.put("firstName", principal.firstName());
      userInfo.put("lastName", principal.lastName());
      userInfo.put("displayName", principal.firstName() + " " + principal.lastName());
      userInfo.put("loginTime", principal.loginTime());

      return ResponseEntity.ok(userInfo);
    }).orElseThrow(() -> new SessionException("Session not found or expired"));
  }

  /**
   * Get detailed session info for UI.
   * Returns structured user and session data.
   */
  @Override
  public ResponseEntity<Map<String, Object>> getSessionInfo() {
    String sessionId = extractSessionId();
    if (sessionId == null) {
      throw new SessionException("No session found");
    }

    Optional<Authentication> authOpt = sessionService.authenticateBySessionId(sessionId, request);

    return authOpt.map(auth -> {
      UserPrincipal principal = (UserPrincipal) auth.getPrincipal();

      Map<String, Object> response = Map.of(
          "user", Map.of(
              "userId", principal.userId(),
              "username", principal.username(),
              "email", principal.email(),
              "firstName", principal.firstName(),
              "lastName", principal.lastName(),
              "displayName", principal.firstName() + " " + principal.lastName()
                        ),
          "session", Map.of(
              "authenticated", true,
              "loginTime", principal.loginTime(),
              "sessionTimeout", principal.sessionTimeout(),
              "lastActivity", System.currentTimeMillis()
                           ),
          "timestamp", System.currentTimeMillis()
                                           );
      return ResponseEntity.ok(response);
    }).orElseThrow(() -> new SessionException("Session not found or expired"));
  }

  /**
   * Get cache statistics for monitoring.
   * Note: This would need to be added to SessionService if needed.
   */
  @Override
  public ResponseEntity<Map<String, Object>> getCacheStats() {
    log.debug("Cache statistics requested");

    // Since getCacheStats() is not available in the current SessionService,
    // return a placeholder or remove this endpoint
    return ResponseEntity.ok(Map.of(
        "message", "Cache statistics not available",
        "timestamp", System.currentTimeMillis()
                                   ));
  }

  /**
   * Extract session ID from secure cookie.
   */
  private String extractSessionId() {
    return CookieUtil.getCookie(request, SESSION_COOKIE_NAME)
        .map(Cookie::getValue)
        .filter(id -> !id.trim().isEmpty())
        .orElse(null);
  }
}
