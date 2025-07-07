package com.example.gateway.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.web.util.WebUtils;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;

/**
 * Cookie Utility for secure session management
 * Uses Spring's ResponseCookie builder for proper cookie handling
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class CookieUtil {

  // Cookie configuration constants
  public static final String SESSION_COOKIE_NAME = "GATEWAY_SESSION_COOKIE"; //change this as per your spec
  private static final String COOKIE_PATH = "/";
  private static final Duration SESSION_TIMEOUT = Duration.ofHours(2);
  private static final String SAME_SITE_STRICT = "Strict";

  // Cookie attribute names for logging
  private static final String DOMAIN_ATTR = "Domain";
  private static final String SECURE_ATTR = "Secure";
  private static final String HTTP_ONLY_ATTR = "HttpOnly";
  private static final String SAME_SITE_ATTR = "SameSite";

  /**
   * Extract cookie by name using Spring's WebUtils
   *
   * @param request HTTP request
   * @param name cookie name
   * @return Optional containing the cookie if found
   */
  public static Optional<Cookie> getCookie(HttpServletRequest request, String name) {
    if (request == null || name == null) {
      return Optional.empty();
    }

    try {
      Cookie cookie = WebUtils.getCookie(request, name);
      return Optional.ofNullable(cookie);
    } catch (Exception e) {
      log.debug("Error retrieving cookie '{}': {}", name, e.getMessage());
      return Optional.empty();
    }
  }

  /**
   * Get decoded cookie value safely
   *
   * @param request HTTP request
   * @param name cookie name
   * @return Optional containing the decoded cookie value
   */
  public static Optional<String> getCookieValue(HttpServletRequest request, String name) {
    return getCookie(request, name)
        .map(Cookie::getValue)
        .filter(value -> value != null && !value.isEmpty())
        .map(CookieUtil::decodeCookieValue);
  }

  /**
   * Set secure session cookie using Spring's ResponseCookie builder
   *
   * @param response HTTP response
   * @param sessionId session identifier
   * @param domain optional domain (null for current domain)
   */
  public static void setSecureSessionCookie(HttpServletResponse response,
                                            String sessionId,
                                            String domain) {
    if (sessionId == null || sessionId.trim().isEmpty()) {
      throw new IllegalArgumentException("Session ID cannot be null or empty");
    }

    // Encode the session ID for safe transport
    String encodedValue = encodeCookieValue(sessionId);

    // Build secure cookie using Spring's ResponseCookie
    ResponseCookie.ResponseCookieBuilder cookieBuilder = ResponseCookie
        .from(SESSION_COOKIE_NAME, encodedValue)
        .httpOnly(true)
        .secure(true)
        .path(COOKIE_PATH)
        .maxAge(SESSION_TIMEOUT)
        .sameSite(SAME_SITE_STRICT);

    // Add domain if specified (for subdomain sharing)
    if (domain != null && !domain.trim().isEmpty()) {
      cookieBuilder.domain(domain);
    }

    ResponseCookie cookie = cookieBuilder.build();

    // Add the cookie to response
    response.addHeader("Set-Cookie", cookie.toString());

    log.debug("Set secure session cookie: name={}, path={}, secure={}, httpOnly={}, sameSite={}",
              SESSION_COOKIE_NAME, COOKIE_PATH, true, true, SAME_SITE_STRICT);
  }

  /**
   * Set secure session cookie for current domain
   */
  public static void setSecureSessionCookie(HttpServletResponse response, String sessionId) {
    setSecureSessionCookie(response, sessionId, null);
  }

  /**
   * Clear session cookie properly
   *
   * @param response HTTP response
   * @param domain optional domain (should match the domain used when setting)
   */
  public static void clearSessionCookie(HttpServletResponse response, String domain) {
    ResponseCookie.ResponseCookieBuilder cookieBuilder = ResponseCookie
        .from(SESSION_COOKIE_NAME, "")
        .httpOnly(true)
        .secure(true)
        .path(COOKIE_PATH)
        .maxAge(0) // Immediate expiration
        .sameSite(SAME_SITE_STRICT);

    if (domain != null && !domain.trim().isEmpty()) {
      cookieBuilder.domain(domain);
    }

    ResponseCookie cookie = cookieBuilder.build();
    response.addHeader("Set-Cookie", cookie.toString());

    log.debug("Cleared session cookie: name={}", SESSION_COOKIE_NAME);
  }

  /**
   * Clear session cookie for current domain
   */
  public static void clearSessionCookie(HttpServletResponse response) {
    clearSessionCookie(response, null);
  }

  /**
   * Create a secure CSRF token cookie
   * Used for additional CSRF protection in sensitive operations
   */
  public static void setCsrfCookie(HttpServletResponse response, String csrfToken, String domain) {
    ResponseCookie cookie = ResponseCookie
        .from("XSRF-TOKEN", csrfToken)
        .httpOnly(false) // JavaScript needs to read this
        .secure(true)
        .path(COOKIE_PATH)
        .maxAge(Duration.ofHours(1))
        .sameSite("Strict")
        .domain(domain)
        .build();

    response.addHeader("Set-Cookie", cookie.toString());
  }

  /**
   * Encode cookie value for safe transport
   */
  private static String encodeCookieValue(String value) {
    try {
      return URLEncoder.encode(value, StandardCharsets.UTF_8);
    } catch (Exception e) {
      log.error("Failed to encode cookie value", e);
      throw new IllegalStateException("Cannot encode cookie value", e);
    }
  }

  /**
   * Decode cookie value safely
   */
  private static String decodeCookieValue(String encodedValue) {
    try {
      return URLDecoder.decode(encodedValue, StandardCharsets.UTF_8);
    } catch (Exception e) {
      log.debug("Failed to decode cookie value: {}", e.getMessage());
      return encodedValue; // Return as-is if decoding fails
    }
  }

  /**
   * Validate session ID format (basic validation)
   *
   * @param sessionId the session ID to validate
   * @return true if valid format
   */
  public static boolean isValidSessionId(String sessionId) {
    if (sessionId == null || sessionId.trim().isEmpty()) {
      return false;
    }

    // Session ID should be base64url encoded and have reasonable length
    // Adjust pattern based on your session ID generation strategy
    return sessionId.matches("^[A-Za-z0-9_-]{32,256}$");
  }

  /**
   * Extract domain from request for cookie domain setting
   * Useful for supporting subdomains
   */
  public static String extractCookieDomain(HttpServletRequest request) {
    String serverName = request.getServerName();

    // For localhost, don't set domain
    if ("localhost".equals(serverName) || serverName.matches("^\\d{1,3}(\\.\\d{1,3}){3}$")) {
      return null;
    }

    // For production domains, you might want to set a parent domain
    // e.g., ".example.com" to share cookies across subdomains
    if (serverName.endsWith(".example.com")) {
      return ".example.com";
    }

    return null; // Use current domain
  }
}
