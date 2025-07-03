package com.example.gateway.adapter.redis.client;

import com.example.gateway.adapter.redis.dto.RedisHealthResponse;
import java.util.Properties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

/**
 * Redis Health Check Client
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RedisHealthClient {

  private final RedisTemplate<String, String> redisTemplate;
  private final RedisConnectionFactory connectionFactory;

  /**
   * Perform comprehensive Redis health check
   */
  public RedisHealthResponse checkHealth() {
    long startTime = System.currentTimeMillis();

    try {
      String pingResponse = redisTemplate.execute((RedisCallback<String>) connection -> {
        return connection.ping();
      });

      if (!"PONG".equals(pingResponse)) {
        return RedisHealthResponse.unhealthy("Invalid PING response: " + pingResponse);
      }

      Properties info = getRedisInfo();
      long responseTime = System.currentTimeMillis() - startTime;

      return RedisHealthResponse.healthy(
          responseTime,
          info.getProperty("redis_version",
                           "unknown"),
          parseMemory(info.getProperty("used_memory",
                                       "0")),
          parseInteger(info.getProperty("connected_clients",
                                        "0"))
                                        );

    } catch (Exception e) {
      log.error("Redis health check failed",
                e);
      return RedisHealthResponse.unhealthy(e.getMessage());
    }
  }

  private Properties getRedisInfo() {
    return redisTemplate.execute((RedisCallback<Properties>) connection -> {
      try {
        Properties props = connection.info();
        return props != null ? props : new Properties();
      } catch (Exception e) {
        log.error("Failed to get Redis INFO",
                  e);
        return new Properties();
      }
    });
  }

  private long parseMemory(String memory) {
    try {
      return Long.parseLong(memory);
    } catch (NumberFormatException e) {
      return 0;
    }
  }

  private int parseInteger(String value) {
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException e) {
      return 0;
    }
  }
}
