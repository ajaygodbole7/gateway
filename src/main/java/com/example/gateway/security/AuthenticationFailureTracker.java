package com.example.gateway.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * Authentication Failure Tracker for brute force protection
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuthenticationFailureTracker {

  private final RedisTemplate<String, String> redisTemplate;

  @Value("${app.security.auth.max-failures:5}")
  private int maxFailures;

  @Value("${app.security.auth.block-duration-minutes:15}")
  private int blockDurationMinutes;

  private static final String FAILURE_COUNT_PREFIX = "auth:fail:count:";
  private static final String BLOCK_PREFIX = "auth:fail:block:";

  /**
   * Record authentication failure
   */
  public void recordFailure(String clientIp) {
    String countKey = FAILURE_COUNT_PREFIX + clientIp;

    try {
      Long failureCount = redisTemplate.opsForValue().increment(countKey);

      if (failureCount == 1) {
        redisTemplate.expire(countKey, 5, TimeUnit.MINUTES);
      }

      log.info("Authentication failure recorded for IP: {} (count: {})",
               maskIpAddress(clientIp), failureCount);

      if (failureCount >= maxFailures) {
        blockIp(clientIp);
      }

    } catch (Exception e) {
      log.error("Error recording authentication failure", e);
    }
  }

  /**
   * Check if IP is blocked
   */
  public boolean isBlocked(String clientIp) {
    String blockKey = BLOCK_PREFIX + clientIp;

    try {
      return Boolean.TRUE.equals(redisTemplate.hasKey(blockKey));
    } catch (Exception e) {
      log.error("Error checking block status", e);
      return false;
    }
  }

  /**
   * Clear failure history
   */
  public void clearFailures(String clientIp) {
    String countKey = FAILURE_COUNT_PREFIX + clientIp;
    String blockKey = BLOCK_PREFIX + clientIp;

    try {
      redisTemplate.delete(countKey);
      redisTemplate.delete(blockKey);
      log.debug("Cleared failure history for IP: {}", maskIpAddress(clientIp));
    } catch (Exception e) {
      log.error("Error clearing failures", e);
    }
  }

  private void blockIp(String clientIp) {
    String blockKey = BLOCK_PREFIX + clientIp;

    try {
      redisTemplate.opsForValue().set(
          blockKey,
          String.valueOf(System.currentTimeMillis()),
          blockDurationMinutes,
          TimeUnit.MINUTES
                                     );

      log.warn("Blocked IP {} for {} minutes due to repeated failures",
               maskIpAddress(clientIp), blockDurationMinutes);

    } catch (Exception e) {
      log.error("Error blocking IP", e);
    }
  }

  private String maskIpAddress(String ip) {
    if (ip == null || !ip.contains(".")) {
      return "***";
    }
    String[] parts = ip.split("\\.");
    if (parts.length == 4) {
      return parts[0] + "." + parts[1] + ".***." + parts[3];
    }
    return "***";
  }
}
