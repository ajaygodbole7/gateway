package com.example.gateway.web.rest.errors;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Handles what happens when someone tries to access a protected endpoint without being logged in.
 *
 * By default, Spring Security redirects to a login page or returns HTML.
 * Since we're an API gateway, we always want to return JSON responses.
 * So instead of redirecting to login (like a website would), we return a 401 JSON error.
 * This lets React/mobile apps handle the error appropriately (e.g., show login screen).
 *
 * This is triggered when:
 * - No session cookie is provided
 * - Session cookie is invalid or expired
 * - SessionAuthenticationFilter rejects the request
 */
@Component
public class DelegatedAuthenticationEntryPoint implements AuthenticationEntryPoint {

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
                       AuthenticationException authException) throws IOException {
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    response.setContentType("application/json");
    response.getWriter().write("{\"error\":\"Not authenticated\",\"message\":\"Authentication required\"}");
  }
}
