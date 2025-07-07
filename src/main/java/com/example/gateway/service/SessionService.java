package com.example.gateway.service;

import com.example.gateway.domain.entity.IdpProvider;
import com.example.gateway.domain.entity.SessionData;
import com.example.gateway.domain.entity.UserPrincipal;
import com.example.gateway.exception.SessionException;
import com.example.gateway.properties.ApplicationProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Session Service - Redis-based session management with cryptographically secure session IDs
 */
@Slf4j
@Service
@Profile("!test")
@RequiredArgsConstructor
public class SessionService {

  // Constants for Session Management
  private static final String SESSION_KEY_PREFIX = "session:";
  private static final String SESSION_DATA_DELIMITER = "|";
  private static final int SESSION_DATA_FIELD_COUNT = 13; // Updated to include IdpProvider

  // Session ID Generation Constants
  private static final int SESSION_ID_ENTROPY_BYTES = 32; // 256 bits
  private static final int SESSION_ID_MIN_LENGTH = 42; // Base64 encoded 32 bytes
  private static final int SESSION_ID_MAX_LENGTH = 44; // With potential padding
  private static final String SESSION_ID_VALID_PATTERN = "^[A-Za-z0-9_-]{" +
      SESSION_ID_MIN_LENGTH + "," + SESSION_ID_MAX_LENGTH + "}$";

  // Secure Random instance (thread-safe)
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  // Dependencies - injected by Lombok's @RequiredArgsConstructor
  private final RedisTemplate<String, String> redisTemplate;
  private final EncryptionService encryptionService;
  private final SessionBindingService sessionBindingService;
  private final ApplicationProperties properties;

  /**
   * Authenticate by session ID
   */
  public Optional<Authentication> authenticateBySessionId(String sessionId, HttpServletRequest request) {
    try {
      // Validate session ID format
      if (!isValidSessionId(sessionId)) {
        log.warn("Invalid session ID format attempted");
        return Optional.empty();
      }

      String sessionKey = SESSION_KEY_PREFIX + sessionId;
      String encryptedData = redisTemplate.opsForValue().get(sessionKey);

      if (encryptedData == null) {
        log.debug("Session not found for ID: {}", maskSessionId(sessionId));
        return Optional.empty();
      }

      String decryptedData = encryptionService.decrypt(encryptedData);
      SessionData session = deserializeSessionData(decryptedData);

      // Check absolute timeout
      long sessionAge = System.currentTimeMillis() - session.createdAt();
      long absoluteTimeoutMillis = TimeUnit.HOURS.toMillis(
          properties.security().session().absoluteTimeoutHours()
                                                          );

      if (sessionAge > absoluteTimeoutMillis) {
        log.info("Session expired due to absolute timeout: {}", maskSessionId(sessionId));
        invalidateSession(sessionId);
        return Optional.empty();
      }

      // Validate client fingerprint
      String currentFingerprint = sessionBindingService.generateClientFingerprint(request);
      if (!session.clientFingerprint().equals(currentFingerprint)) {
        log.warn("Session fingerprint mismatch for session: {}", maskSessionId(sessionId));
        invalidateSession(sessionId);
        return Optional.empty();
      }

      // Refresh session TTL
      int slidingWindowMinutes = properties.security().session().slidingWindowMinutes();
      redisTemplate.expire(sessionKey, slidingWindowMinutes, TimeUnit.MINUTES);

      return Optional.of(new UsernamePasswordAuthenticationToken(
          session.userPrincipal(), null, Collections.emptyList()
      ));

    } catch (Exception e) {
      log.error("Session authentication failed for session: {}", maskSessionId(sessionId), e);
      return Optional.empty();
    }
  }

  /**
   * Create authenticated session
   * @param idpProvider The identity provider that authenticated this user
   * @param userPrincipal The authenticated user's principal
   * @param idToken The user's ID token (will be encrypted)
   * @param request The HTTP request for fingerprinting
   */
  public String createAuthenticatedSession(IdpProvider idpProvider,
                                           UserPrincipal userPrincipal,
                                           String idToken,
                                           HttpServletRequest request) {
    String sessionId = generateSecureSessionId();

    try {
      SessionData sessionData = new SessionData(
          idpProvider,
          userPrincipal,
          idToken,
          System.currentTimeMillis(),
          System.currentTimeMillis(),
          sessionBindingService.generateClientFingerprint(request),
          sessionBindingService.getClientIpAddress(request)
      );

      String serializedData = serializeSessionData(sessionData);
      String encryptedData = encryptionService.encrypt(serializedData);

      String sessionKey = SESSION_KEY_PREFIX + sessionId;
      int slidingWindowMinutes = properties.security().session().slidingWindowMinutes();

      redisTemplate.opsForValue().set(
          sessionKey,
          encryptedData,
          slidingWindowMinutes,
          TimeUnit.MINUTES
                                     );

      log.info("Created session for user: {} via provider: {}",
               userPrincipal.userId(), idpProvider);
      return sessionId;

    } catch (Exception e) {
      log.error("Failed to create session for user: {}", userPrincipal.userId(), e);
      throw new SessionException("Failed to create session", e);
    }
  }

  /**
   * Check if session exists and is valid
   */
  public boolean isSessionValid(String sessionId) {
    if (!isValidSessionId(sessionId)) {
      return false;
    }

    String sessionKey = SESSION_KEY_PREFIX + sessionId;
    return Boolean.TRUE.equals(redisTemplate.hasKey(sessionKey));
  }

  /**
   * Refresh session TTL
   */
  public boolean refreshSession(String sessionId) {
    if (!isValidSessionId(sessionId)) {
      return false;
    }

    String sessionKey = SESSION_KEY_PREFIX + sessionId;
    int slidingWindowMinutes = properties.security().session().slidingWindowMinutes();
    Boolean refreshed = redisTemplate.expire(sessionKey, slidingWindowMinutes, TimeUnit.MINUTES);

    if (Boolean.TRUE.equals(refreshed)) {
      log.debug("Refreshed session: {}", maskSessionId(sessionId));
    }

    return Boolean.TRUE.equals(refreshed);
  }

  /**
   * Invalidate session
   */
  public void invalidateSession(String sessionId) {
    if (!isValidSessionId(sessionId)) {
      return;
    }

    String sessionKey = SESSION_KEY_PREFIX + sessionId;
    redisTemplate.delete(sessionKey);
    log.info("Invalidated session: {}", maskSessionId(sessionId));
  }

  /**
   * Get session data (for debugging/monitoring)
   */
  public Optional<String> getSessionData(String sessionId) {
    if (!isValidSessionId(sessionId)) {
      return Optional.empty();
    }

    String sessionKey = SESSION_KEY_PREFIX + sessionId;
    return Optional.ofNullable(redisTemplate.opsForValue().get(sessionKey));
  }

  /**
   * Generates a cryptographically secure session ID.
   * Uses 256 bits of entropy to prevent brute force attacks.
   */
  private String generateSecureSessionId() {
    byte[] randomBytes = new byte[SESSION_ID_ENTROPY_BYTES];
    SECURE_RANDOM.nextBytes(randomBytes);

    String sessionId = Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(randomBytes);

    // Verify the generated ID meets our criteria
    if (!isValidSessionId(sessionId)) {
      throw new SessionException("Generated session ID failed validation");
    }

    return sessionId;
  }

  /**
   * Validates session ID format to prevent injection attacks.
   * Session IDs must be Base64 URL-encoded strings of expected length.
   */
  private boolean isValidSessionId(String sessionId) {
    if (sessionId == null || sessionId.isEmpty()) {
      return false;
    }

    return sessionId.matches(SESSION_ID_VALID_PATTERN);
  }

  /**
   * Mask session ID for logging (show first 8 chars only)
   */
  private String maskSessionId(String sessionId) {
    if (sessionId == null || sessionId.length() < 8) {
      return "INVALID";
    }
    return sessionId.substring(0, 8) + "...";
  }

  /**
   * Serialize session data using delimiter-separated format
   */
  private String serializeSessionData(SessionData session) {
    UserPrincipal principal = session.userPrincipal();

    return String.join(SESSION_DATA_DELIMITER,
                       session.idpProvider().name(), // New field
                       principal.userId(),
                       principal.username(),
                       principal.email(),
                       principal.firstName(),
                       principal.lastName(),
                       String.valueOf(principal.loginTime()),
                       String.valueOf(principal.sessionTimeout()),
                       session.idToken(),
                       String.valueOf(session.createdAt()),
                       String.valueOf(session.lastAccessed()),
                       session.clientFingerprint(),
                       session.lastIpAddress()
                      );
  }

  /**
   * Deserialize session data from delimiter-separated format
   */
  private SessionData deserializeSessionData(String data) {
    String[] parts = data.split("\\" + SESSION_DATA_DELIMITER, -1);

    if (parts.length != SESSION_DATA_FIELD_COUNT) {
      throw new SessionException("Invalid session data format: expected " +
                                     SESSION_DATA_FIELD_COUNT + " fields, got " + parts.length);
    }

    try {
      IdpProvider idpProvider = IdpProvider.valueOf(parts[0]); // Parse provider

      UserPrincipal principal = new UserPrincipal(
          parts[1], // userId
          parts[2], // username
          parts[3], // email
          parts[4], // firstName
          parts[5], // lastName
          Long.parseLong(parts[6]), // loginTime
          Long.parseLong(parts[7])  // sessionTimeout
      );

      return new SessionData(
          idpProvider,
          principal,
          parts[8], // idToken
          Long.parseLong(parts[9]),   // createdAt
          Long.parseLong(parts[10]),  // lastAccessed
          parts[11], // clientFingerprint
          parts[12]  // lastIpAddress
      );
    } catch (IllegalArgumentException e) {
      throw new SessionException("Invalid IdpProvider in session data: " + parts[0], e);
    } catch (NumberFormatException e) {
      throw new SessionException("Invalid session data: corrupted numeric fields", e);
    }
  }
}
