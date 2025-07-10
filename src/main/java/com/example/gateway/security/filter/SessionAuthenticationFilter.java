package com.example.gateway.security.filter;

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
 * A simple and robust filter that authenticates users based on the app_session cookie.
 * It delegates all session validation logic to the SessionService.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SessionAuthenticationFilter extends OncePerRequestFilter {

  private static final String SESSION_COOKIE_NAME = "app_session";
  private final SessionService sessionService;

  @Override
  protected void doFilterInternal(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain
                                 ) throws ServletException, IOException {

    Optional<Cookie> sessionCookie = CookieUtil.getCookie(request, SESSION_COOKIE_NAME);

    if (sessionCookie.isPresent()) {
      String sessionId = sessionCookie.get().getValue();
      try {
        // Delegate the entire authentication process to the SessionService.
        // This single method call handles L1/L2 caching, Redis interaction,
        // fingerprint validation, and selective TTL refresh.
        Optional<Authentication> authOptional = sessionService.authenticateBySessionId(sessionId, request);

        if (authOptional.isPresent()) {
          // If the service returns a valid Authentication object, populate the context.
          SecurityContextHolder.getContext().setAuthentication(authOptional.get());
          log.trace("SessionAuthenticationFilter: Successfully authenticated session {}", sessionId);
        } else {
          // The session was invalid (expired, not found, fingerprint mismatch, etc.).
          // SessionService has already invalidated it. We just need to clear the cookie.
          log.debug("SessionAuthenticationFilter: Invalid session ID provided. Clearing cookie.");
          CookieUtil.clearSessionCookie(response);
        }
      } catch (Exception e) {
        // Catch any unexpected errors from the session service to prevent filter chain failure.
        log.error("An unexpected error occurred during session authentication.", e);
        CookieUtil.clearSessionCookie(response);
      }
    }

    filterChain.doFilter(request, response);
  }
}
