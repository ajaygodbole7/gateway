package com.example.gateway.config;

import okhttp3.ConnectionPool;
import okhttp3.Dispatcher;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;

/**
 * Optimized OkHttp Client Configuration
 *
 * Shared connection pool and dispatcher for all HTTP clients
 * to minimize connection overhead and improve latency
 */
@Configuration
public class HttpClientConfig {

  @Value("${app.http.client.max-idle-connections:20}")
  private int maxIdleConnections;

  @Value("${app.http.client.keep-alive-duration:5}")
  private long keepAliveDuration;

  @Value("${app.http.client.max-requests:100}")
  private int maxRequests;

  @Value("${app.http.client.max-requests-per-host:20}")
  private int maxRequestsPerHost;

  /**
   * Shared connection pool to reduce connection establishment overhead
   */
  @Bean
  public ConnectionPool sharedConnectionPool() {
    return new ConnectionPool(maxIdleConnections, keepAliveDuration, TimeUnit.MINUTES);
  }

  /**
   * Shared dispatcher for concurrent request management
   */
  @Bean
  public Dispatcher sharedDispatcher() {
    Dispatcher dispatcher = new Dispatcher();
    dispatcher.setMaxRequests(maxRequests);
    dispatcher.setMaxRequestsPerHost(maxRequestsPerHost);
    return dispatcher;
  }

  /**
   * Default HTTP client for OAuth2 and general use
   */
  @Bean
  public OkHttpClient defaultOkHttpClient(ConnectionPool connectionPool, Dispatcher dispatcher) {
    return new OkHttpClient.Builder()
        .connectionPool(connectionPool)
        .dispatcher(dispatcher)
        .protocols(Arrays.asList(Protocol.HTTP_2, Protocol.HTTP_1_1))
        .connectTimeout(3, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .writeTimeout(5, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .followRedirects(false)
        .followSslRedirects(false)
        .build();
  }

  /**
   * Fast HTTP client for critical paths (Key Vault, health checks)
   */
  @Bean(name = "fastOkHttpClient")
  public OkHttpClient fastOkHttpClient(ConnectionPool connectionPool, Dispatcher dispatcher) {
    return new OkHttpClient.Builder()
        .connectionPool(connectionPool)
        .dispatcher(dispatcher)
        .protocols(Arrays.asList(Protocol.HTTP_2, Protocol.HTTP_1_1))
        .connectTimeout(1, TimeUnit.SECONDS)
        .readTimeout(2, TimeUnit.SECONDS)
        .writeTimeout(2, TimeUnit.SECONDS)
        .retryOnConnectionFailure(false)
        .build();
  }
}
