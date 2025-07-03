package com.example.gateway.web.rest.controller;



import com.example.gateway.domain.entity.UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

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

    if (auth == null || !auth.isAuthenticated()) {
      log.error("Unexpected: SessionController received unauthenticated request");
      return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
    }

    UserPrincipal principal = (UserPrincipal) auth.getPrincipal();

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

    if (auth == null || !auth.isAuthenticated()) {
      return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
    }

    UserPrincipal principal = (UserPrincipal) auth.getPrincipal();

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
