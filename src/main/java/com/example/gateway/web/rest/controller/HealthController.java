package com.example.gateway.web.rest.controller;


import com.example.gateway.adapter.redis.client.RedisHealthClient;
import com.example.gateway.adapter.redis.dto.RedisHealthResponse;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Health Check Controller
 */
@Slf4j
@RestController
@RequestMapping("/health")
@RequiredArgsConstructor
public class HealthController {

  private final RedisHealthClient redisHealthClient;

  /**
   * Basic health check
   */
  @GetMapping
  public ResponseEntity<?> health() {
    return ResponseEntity.ok(Map.of(
        "status",
        "UP",
        "timestamp",
        System.currentTimeMillis()
                                   ));
  }

  /**
   * Liveness probe
   */
  @GetMapping("/live")
  public ResponseEntity<?> liveness() {
    Runtime runtime = Runtime.getRuntime();
    long maxMemory = runtime.maxMemory();
    long totalMemory = runtime.totalMemory();
    long freeMemory = runtime.freeMemory();
    long usedMemory = totalMemory - freeMemory;

    double memoryUsagePercent = (double) usedMemory / maxMemory * 100;

    if (memoryUsagePercent < 90) {
      return ResponseEntity.ok(Map.of(
          "status",
          "LIVE",
          "memoryUsagePercent",
          memoryUsagePercent
                                     ));
    }

    return ResponseEntity.status(503).body(Map.of(
        "status",
        "DEAD",
        "memoryUsagePercent",
        memoryUsagePercent
                                                 ));
  }

  /**
   * Readiness probe
   */
  @GetMapping("/ready")
  public ResponseEntity<?> readiness() {
    Map<String, Object> status = new HashMap<>();
    boolean isReady = true;

    // Check Redis connectivity
    RedisHealthResponse redisHealth = redisHealthClient.checkHealth();
    status.put("redis",
               Map.of(
                   "status",
                   redisHealth.healthy() ? "UP" : "DOWN",
                   "responseTimeMs",
                   redisHealth.responseTimeMs(),
                   "error",
                   redisHealth.error()
                     ));

    if (!redisHealth.healthy() || redisHealth.responseTimeMs() > 100) {
      isReady = false;
    }

    status.put("ready",
               isReady);
    status.put("timestamp",
               System.currentTimeMillis());

    return ResponseEntity.status(isReady ? 200 : 503).body(status);
  }
}
