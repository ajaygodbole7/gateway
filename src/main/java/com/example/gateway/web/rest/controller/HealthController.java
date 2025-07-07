package com.example.gateway.web.rest.controller;

import com.example.gateway.adapter.redis.client.RedisHealthClient;
import com.example.gateway.adapter.redis.dto.RedisHealthResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Health Check Controller
 *
 * Note: Health endpoints typically don't throw exceptions to GlobalErrorHandler
 * as they need to return specific status codes for monitoring tools.
 */
@Slf4j
@RestController
@RequestMapping("/health")
@RequiredArgsConstructor
public class HealthController {

  // Constants for health check thresholds
  private static final double MEMORY_USAGE_CRITICAL_PERCENT = 90.0;
  private static final long REDIS_RESPONSE_TIME_WARNING_MS = 100L;
  private static final String STATUS_UP = "UP";
  private static final String STATUS_DOWN = "DOWN";
  private static final String STATUS_LIVE = "LIVE";
  private static final String STATUS_DEAD = "DEAD";

  private final RedisHealthClient redisHealthClient;

  /**
   * Basic health check
   */
  @GetMapping
  public ResponseEntity<Map<String, Object>> health() {
    return ResponseEntity.ok(Map.of(
        "status", STATUS_UP,
        "timestamp", System.currentTimeMillis()
                                   ));
  }

  /**
   * Liveness probe - checks JVM health
   */
  @GetMapping("/live")
  public ResponseEntity<Map<String, Object>> liveness() {
    Runtime runtime = Runtime.getRuntime();
    long maxMemory = runtime.maxMemory();
    long totalMemory = runtime.totalMemory();
    long freeMemory = runtime.freeMemory();
    long usedMemory = totalMemory - freeMemory;

    double memoryUsagePercent = (double) usedMemory / maxMemory * 100;

    Map<String, Object> response = new HashMap<>();
    response.put("memoryUsagePercent", String.format("%.2f", memoryUsagePercent));

    if (memoryUsagePercent < MEMORY_USAGE_CRITICAL_PERCENT) {
      response.put("status", STATUS_LIVE);
      return ResponseEntity.ok(response);
    }

    log.warn("Liveness check failed: memory usage {}%", memoryUsagePercent);
    response.put("status", STATUS_DEAD);
    return ResponseEntity.status(503).body(response);
  }

  /**
   * Readiness probe - checks external dependencies
   */
  @GetMapping("/ready")
  public ResponseEntity<Map<String, Object>> readiness() {
    Map<String, Object> status = new HashMap<>();
    boolean isReady = true;

    // Check Redis connectivity
    RedisHealthResponse redisHealth;
    try {
      redisHealth = redisHealthClient.checkHealth();
    } catch (Exception e) {
      // For health checks, we don't want to throw to GlobalErrorHandler
      log.error("Redis health check failed", e);
      redisHealth = RedisHealthResponse.unhealthy(e.getMessage());
    }

    Map<String, Object> redisStatus = new HashMap<>();
    redisStatus.put("status", redisHealth.healthy() ? STATUS_UP : STATUS_DOWN);
    redisStatus.put("responseTimeMs", redisHealth.responseTimeMs());

    if (redisHealth.error() != null) {
      redisStatus.put("error", redisHealth.error());
    }

    status.put("redis", redisStatus);

    // Determine overall readiness
    if (!redisHealth.healthy() || redisHealth.responseTimeMs() > REDIS_RESPONSE_TIME_WARNING_MS) {
      isReady = false;
      log.warn("Readiness check failed: Redis health={}, responseTime={}ms",
               redisHealth.healthy(), redisHealth.responseTimeMs());
    }

    status.put("ready", isReady);
    status.put("timestamp", System.currentTimeMillis());

    return ResponseEntity.status(isReady ? 200 : 503).body(status);
  }
}
