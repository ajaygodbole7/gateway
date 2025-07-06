package com.example.gateway.security.filter;

import com.example.gateway.domain.entity.SessionData;
import com.example.gateway.service.SessionService;
import com.example.gateway.util.CookieUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * Session Authentication Filter
 *
 * Validates session cookies and populates Spring Security context
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SessionAuthenticationFilter extends OncePerRequestFilter {

  private final SessionService sessionService;
  private static final String SESSION_COOKIE_NAME = "app_session";

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                  FilterChain filterChain) throws ServletException, IOException {
    Optional<Cookie> sessionCookie = CookieUtil.getCookie(request, SESSION_COOKIE_NAME);

    if (sessionCookie.isPresent()) {
      String sessionId = sessionCookie.get().getValue();

      try {
        // Get session data
        Optional<String> encryptedData = sessionService.getSessionData(sessionId);
        if (encryptedData.isEmpty()) {
          invalidateAndClear(sessionId, response);
          filterChain.doFilter(request, response);
          return;
        }

        // Decrypt session data
        String decryptedData;
        try {
          decryptedData = encryptionService.decrypt(encryptedData.get());
        } catch (Exception e) {
          log.error("FATAL: Session decryption failed for session: {}", sessionId, e);
          invalidateAndClear(sessionId, response);
          filterChain.doFilter(request, response);
          return;
        }

        // Validate token with IdP
        SessionData sessionData = objectMapper.readValue(decryptedData, SessionData.class);
        Optional<TokenValidationResult> validationResult = validateToken(sessionData);

        if (validationResult.isEmpty()) {
          log.warn("Token validation failed for session: {}", sessionId);
          SecurityEventLogger.logTokenValidationFailure(
              sessionData.userPrincipal().userId(),
              "Token inactive or revoked"
                                                       );
          invalidateAndClear(sessionId, response);
          filterChain.doFilter(request, response);
          return;
        }

        // Set authentication
        Authentication auth = createAuthentication(sessionData.userPrincipal());
        SecurityContextHolder.getContext().setAuthentication(auth);

      } catch (Exception e) {
        log.error("Unexpected error during session authentication", e);
        invalidateAndClear(sessionId, response);
      }
    }

    filterChain.doFilter(request, response);
  }

  private void invalidateAndClear(String sessionId, HttpServletResponse response) {
    sessionService.invalidateSession(sessionId);
    CookieUtil.clearSessionCookie(response);
  }
}
