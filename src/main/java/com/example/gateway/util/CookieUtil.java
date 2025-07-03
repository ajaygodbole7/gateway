package com.example.gateway.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Optional;

/**
 * Cookie Utility for secure session management
 */
public class CookieUtil {

  private static final String SESSION_COOKIE_NAME = "app_session";

  /**
   * Extract cookie by name
   */
  public static Optional<Cookie> getCookie(HttpServletRequest request,
                                           String name) {
    Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return Optional.empty();
    }
    return Arrays.stream(cookies)
        .filter(cookie -> name.equals(cookie.getName()))
        .findFirst();
  }

  /**
   * Set secure session cookie
   */
  public static void setSecureSessionCookie(HttpServletResponse response,
                                            String sessionId) {
    Cookie cookie = new Cookie(SESSION_COOKIE_NAME,
                               sessionId);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setPath("/");
    cookie.setMaxAge(-1); // Session cookie

    // Add SameSite=Strict via header
    response.addHeader("Set-Cookie",
                       String.format(
                           "%s=%s; Path=/; HttpOnly; Secure; SameSite=Strict",
                           SESSION_COOKIE_NAME,
                           sessionId
                                    ));
  }

  /**
   * Clear session cookie
   */
  public static void clearSessionCookie(HttpServletResponse response) {
    Cookie cookie = new Cookie(SESSION_COOKIE_NAME,
                               "");
    cookie.setPath("/");
    cookie.setMaxAge(0);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    response.addCookie(cookie);
  }
}
