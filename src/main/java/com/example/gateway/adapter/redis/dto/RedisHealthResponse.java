package com.example.gateway.adapter.redis.dto;

/**
 * Redis Health Check Response
 */
public record RedisHealthResponse(
    boolean healthy,
    long responseTimeMs,
    String version,
    long usedMemoryBytes,
    int connectedClients,
    String error
) {
  public static RedisHealthResponse healthy(long responseTimeMs, String version,
                                            long usedMemoryBytes, int connectedClients) {
    return new RedisHealthResponse(true, responseTimeMs, version,
                                   usedMemoryBytes, connectedClients, null);
  }

  public static RedisHealthResponse unhealthy(String error) {
    return new RedisHealthResponse(false, 0, null, 0, 0, error);
  }
}
