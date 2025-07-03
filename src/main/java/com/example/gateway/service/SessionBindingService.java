package com.example.gateway.service;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Session Binding Service for client fingerprinting
 */
@Slf4j
@Service
public class SessionBindingService {

  /**
   * Generate client fingerprint for session binding
   */
  public String generateClientFingerprint(HttpServletRequest request) {
    StringBuilder fingerprintData = new StringBuilder();

    String userAgent = request.getHeader("User-Agent");
    String acceptLanguage = request.getHeader("Accept-Language");
    String acceptEncoding = request.getHeader("Accept-Encoding");

    fingerprintData.append("ua:").append(userAgent != null ? userAgent : "unknown");
    fingerprintData.append("|lang:").append(acceptLanguage != null ? acceptLanguage : "unknown");
    fingerprintData.append("|enc:").append(acceptEncoding != null ? acceptEncoding : "unknown");

    String fingerprint = generateSHA256Hash(fingerprintData.toString());
    log.debug("Generated client fingerprint: {}", fingerprint);
    return fingerprint;
  }

  /**
   * Extract client IP address
   */
  public String getClientIpAddress(HttpServletRequest request) {
    String xForwardedFor = request.getHeader("X-Forwarded-For");
    if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
      return xForwardedFor.split(",")[0].trim();
    }

    String xRealIp = request.getHeader("X-Real-IP");
    if (xRealIp != null && !xRealIp.isEmpty()) {
      return xRealIp;
    }

    return request.getRemoteAddr();
  }

  private String generateSHA256Hash(String input) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    } catch (NoSuchAlgorithmException e) {
      log.error("SHA-256 algorithm not available", e);
      throw new RuntimeException("Failed to generate fingerprint", e);
    }
  }
}
