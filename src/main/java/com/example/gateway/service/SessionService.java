package com.example.gateway.service;

import com.example.gateway.domain.entity.SessionData;
import com.example.gateway.domain.entity.UserPrincipal;
import com.example.gateway.exception.SessionException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Session Service - Simple Redis-based session management
 */
@Slf4j
@Service
@Profile("!test")
@RequiredArgsConstructor
public class SessionService {

  private final RedisTemplate<String, String> redisTemplate;
  private final EncryptionService encryptionService;
  private final SessionBindingService sessionBindingService;
  private final DistributedLockService lockService;

  @Value("${app.security.session.sliding-window-minutes:30}")
  private int slidingWindowMinutes;

  @Value("${app.security.session.absolute-timeout-hours:8}")
  private int absoluteTimeoutHours;

  private static final String SESSION_PREFIX = "session:";
  private static final SecureRandom secureRandom = new SecureRandom();

  /**
   * Authenticate by session ID
   */
  public Optional<Authentication> authenticateBySessionId(String sessionId, HttpServletRequest request) {
    try {
      String encryptedData = redisTemplate.opsForValue().get(SESSION_PREFIX + sessionId);
      if (encryptedData == null) {
        return Optional.empty();
      }

      String decryptedData = encryptionService.decrypt(encryptedData);
      SessionData session = deserializeSessionData(decryptedData);

      // Basic validation
      if (System.currentTimeMillis() - session.createdAt() > TimeUnit.HOURS.toMillis(absoluteTimeoutHours)) {
        invalidateSession(sessionId);
        return Optional.empty();
      }

      // Validate fingerprint
      String currentFingerprint = sessionBindingService.generateClientFingerprint(request);
      if (!session.clientFingerprint().equals(currentFingerprint)) {
        invalidateSession(sessionId);
        return Optional.empty();
      }

      // Update TTL
      redisTemplate.expire(SESSION_PREFIX + sessionId, slidingWindowMinutes, TimeUnit.MINUTES);

      return Optional.of(new UsernamePasswordAuthenticationToken(
          session.userPrincipal(), null, Collections.emptyList()
      ));

    } catch (Exception e) {
      log.error("Session authentication failed", e);
      return Optional.empty();
    }
  }

  /**
   * Create authenticated session
   */
  public String createAuthenticatedSession(UserPrincipal userPrincipal, String idToken, HttpServletRequest request) {
    String sessionId = generateSessionId();

    try {
      SessionData sessionData = new SessionData(
          userPrincipal,
          idToken,
          System.currentTimeMillis(),
          System.currentTimeMillis(),
          sessionBindingService.generateClientFingerprint(request),
          sessionBindingService.getClientIpAddress(request)
      );

      String serializedData = serializeSessionData(sessionData);
      String encryptedData = encryptionService.encrypt(serializedData);

      redisTemplate.opsForValue().set(
          SESSION_PREFIX + sessionId,
          encryptedData,
          slidingWindowMinutes,
          TimeUnit.MINUTES
                                     );

      return sessionId;

    } catch (Exception e) {
      throw new SessionException("Failed to create session", e);
    }
  }

  /**
   * Check if session exists
   */
  public boolean isSessionValid(String sessionId) {
    return Boolean.TRUE.equals(redisTemplate.hasKey(SESSION_PREFIX + sessionId));
  }

  /**
   * Refresh session TTL
   */
  public boolean refreshSession(String sessionId) {
    return Boolean.TRUE.equals(
        redisTemplate.expire(SESSION_PREFIX + sessionId, slidingWindowMinutes, TimeUnit.MINUTES)
                              );
  }

  /**
   * Invalidate session
   */
  public void invalidateSession(String sessionId) {
    redisTemplate.delete(SESSION_PREFIX + sessionId);
  }

  private String generateSessionId() {
    byte[] randomBytes = new byte[32];
    secureRandom.nextBytes(randomBytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
  }

  private String serializeSessionData(SessionData session) {
    return String.join("|",
                       session.userPrincipal().userId(),
                       session.userPrincipal().username(),
                       session.userPrincipal().email(),
                       session.userPrincipal().firstName(),
                       session.userPrincipal().lastName(),
                       String.valueOf(session.userPrincipal().loginTime()),
                       String.valueOf(session.userPrincipal().sessionTimeout()),
                       session.idToken(),
                       String.valueOf(session.createdAt()),
                       String.valueOf(session.lastAccessed()),
                       session.clientFingerprint(),
                       session.lastIpAddress()
                      );
  }

  private SessionData deserializeSessionData(String data) {
    String[] parts = data.split("\\|", -1);
    if (parts.length != 12) {
      throw new SessionException("Invalid session data format");
    }

    UserPrincipal principal = new UserPrincipal(
        parts[0], parts[1], parts[2], parts[3], parts[4],
        Long.parseLong(parts[5]), Long.parseLong(parts[6])
    );

    return new SessionData(
        principal, parts[7],
        Long.parseLong(parts[8]), Long.parseLong(parts[9]),
        parts[10], parts[11]
    );
  }
}
