package com.example.gateway.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;

/**
 * Simple distributed lock using Redis
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DistributedLockService {

  private final RedisTemplate<String, String> redisTemplate;
  private static final String LOCK_PREFIX = "lock:";

  public String tryAcquireLock(String lockKey, Duration duration) {
    String fullKey = LOCK_PREFIX + lockKey;
    String lockToken = UUID.randomUUID().toString();

    Boolean acquired = redisTemplate.opsForValue()
        .setIfAbsent(fullKey, lockToken, duration);

    return Boolean.TRUE.equals(acquired) ? lockToken : null;
  }

  public boolean releaseLock(String lockKey, String lockToken) {
    String fullKey = LOCK_PREFIX + lockKey;
    String currentToken = redisTemplate.opsForValue().get(fullKey);

    if (lockToken.equals(currentToken)) {
      redisTemplate.delete(fullKey);
      return true;
    }
    return false;
  }
}
