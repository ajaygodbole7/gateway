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

    log.debug("Processing session authentication for: {} {}",
              request.getMethod(), request.getRequestURI());

    Optional<Cookie> sessionCookie = CookieUtil.getCookie(request, SESSION_COOKIE_NAME);

    if (sessionCookie.isPresent()) {
      String sessionId = sessionCookie.get().getValue();
      log.debug("Found session cookie: {}", sessionId.substring(0, 8) + "***");

      try {
        Optional<Authentication> auth = sessionService.authenticateBySessionId(sessionId, request);

        if (auth.isPresent()) {
          SecurityContextHolder.getContext().setAuthentication(auth.get());
          log.debug("Authentication successful for user: {}", auth.get().getName());
        } else {
          log.debug("Session validation failed");
        }

      } catch (Exception e) {
        log.warn("Session authentication error", e);
      }
    } else {
      log.debug("No session cookie found in request");
    }

    filterChain.doFilter(request, response);
  }
}
