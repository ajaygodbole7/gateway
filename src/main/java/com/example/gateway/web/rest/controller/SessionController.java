package com.example.gateway.web.rest.controller;

import com.example.gateway.domain.entity.UserPrincipal;
import com.example.gateway.exception.SessionException;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller implementation for session management.
 * Provides session and user information for the React UI.
 */
@RestController
@Slf4j
@RequiredArgsConstructor
public class SessionController implements SessionAPI {

  @Override
  public ResponseEntity<Map<String, Object>> getCurrentUser() {
    log.debug("REST request to get current user");

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();

    // This should not happen if SecurityFilterChain is configured correctly
    // Let GlobalErrorHandler handle it via AuthenticationException
    if (auth == null || !auth.isAuthenticated() || auth.getPrincipal() == null) {
      throw new SessionException("No authenticated session found");
    }

    // Validate principal type
    if (!(auth.getPrincipal() instanceof UserPrincipal principal)) {
      log.error("Invalid principal type: {}", auth.getPrincipal().getClass());
      throw new SessionException("Invalid session data");
    }

    return ResponseEntity.ok(Map.of(
        "userId", principal.userId(),
        "username", principal.username(),
        "email", principal.email(),
        "firstName", principal.firstName(),
        "lastName", principal.lastName(),
        "displayName", principal.firstName() + " " + principal.lastName()
                                   ));
  }

  @Override
  public ResponseEntity<Map<String, Object>> getSessionInfo() {
    log.debug("REST request to get session info");

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();

    if (auth == null || !auth.isAuthenticated() || auth.getPrincipal() == null) {
      throw new SessionException("No authenticated session found");
    }

    if (!(auth.getPrincipal() instanceof UserPrincipal principal)) {
      throw new SessionException("Invalid session data");
    }

    return ResponseEntity.ok(Map.of(
        "user", Map.of(
            "userId", principal.userId(),
            "username", principal.username(),
            "email", principal.email()
                      ),
        "session", Map.of(
            "authenticated", true,
            "loginTime", principal.loginTime(),
            "expiresIn", principal.sessionTimeout()
                         )
                                   ));
  }
}
