package com.example.gateway.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.boot.convert.DurationUnit;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * Centralized configuration properties for the Security Gateway application.
 * Uses records for immutability and type safety.
 */
@Validated
@ConfigurationProperties(prefix = "app")
public record ApplicationProperties(
    @NotNull @Valid FrontendProperties frontend,
    @NotNull @Valid AuthProperties auth,
    @NotNull @Valid M2mProperties m2m,
    @NotNull @Valid SecurityProperties security,
    @NotNull @Valid OkHttpProperties http,
    @NotNull @Valid AzureProperties azure,
    @NotNull @Valid RedisProperties redis,
    @NotNull @Valid CacheProperties cache
) {

  /**
   * Frontend application configuration
   */
  public record FrontendProperties(@NotBlank String url) {}

  /**
   * OAuth2/OIDC authentication configuration
   */
  public record AuthProperties(
      @NotNull @Valid PingProperties ping,
      @NotNull @Valid EntraProperties entra,
      @NotNull List<String> allowedReturnPaths
  ) {
    public record PingProperties(
        @NotBlank String clientId,
        @NotBlank String authorizationUri,
        @NotBlank String tokenUri,
        @NotBlank String validationUri,
        @NotBlank String jwksUri,
        @NotBlank String issuerUri
    ) {}

    public record EntraProperties(
        @NotBlank String authority,
        @NotBlank String clientId,
        @NotBlank String issuerUri,
        @NotBlank String validationUri,
        @NotBlank String gatewayM2mAudience
    ) {}
  }

  /**
   * Machine-to-machine token management configuration
   */
  public record M2mProperties(
      @NotNull @Valid RefreshProperties refresh,
      @NotNull @Valid RetryProperties retry
  ) {
    public record RefreshProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("60s") @DurationUnit(ChronoUnit.SECONDS) Duration rate,
        @DefaultValue("60s") @DurationUnit(ChronoUnit.SECONDS) Duration initialDelay
    ) {}

    public record RetryProperties(
        @DefaultValue("15") @Positive int maxAttempts,
        @DefaultValue("300ms") @DurationUnit(ChronoUnit.MILLIS) Duration delay
    ) {}
  }

  /**
   * Security configuration
   */
  public record SecurityProperties(
      @NotNull @Valid AuthSecurityProperties auth,
      @NotNull @Valid SessionProperties session,
      String requiredAcr,
      List<String> requiredAmr,
      Long maxAuthAge
  ) {
    public record AuthSecurityProperties(
        @DefaultValue("5") @Positive int maxFailures,
        @DefaultValue("15") @Positive int blockDurationMinutes
    ) {}

    public record SessionProperties(
        @DefaultValue("30") @Positive int slidingWindowMinutes,
        @DefaultValue("8") @Positive int absoluteTimeoutHours
    ) {}
  }

  /**
   * OkHttp client configuration
   */
  public record OkHttpProperties(
      @NotNull @Valid ClientProperties client
  ) {
    public record ClientProperties(
        @DefaultValue("20") @Positive int maxIdleConnections,
        @DefaultValue("5") @Positive int keepAliveDurationMinutes,
        @DefaultValue("100") @Positive int maxRequests,
        @DefaultValue("20") @Positive int maxRequestsPerHost
    ) {}
  }

  /**
   * Azure services configuration
   */
  public record AzureProperties(@NotNull @Valid KeyVaultProperties keyVault) {
    public record KeyVaultProperties(@NotBlank String uri) {}
  }

  /**
   * Redis configuration with cluster support
   */
  public record RedisProperties(
      @DefaultValue("standalone") @Pattern(regexp = "standalone|cluster") String mode,
      @DefaultValue("localhost") @NotBlank String host,
      @DefaultValue("6380") @Min(1) @Max(65535) int port,
      @NotNull @Valid SslProperties ssl,
      @Valid ClusterProperties cluster,
      @DefaultValue("2s") @DurationUnit(ChronoUnit.SECONDS) Duration timeout,
      @NotNull @Valid PoolProperties pool
  ) {
    public record SslProperties(
        @DefaultValue("true") boolean enabled
    ) {}

    public record ClusterProperties(
        String nodes,
        @DefaultValue("3") @Min(0) @Max(5) int maxRedirects
    ) {}

    public record PoolProperties(
        @DefaultValue("16") @Positive int maxActive,
        @DefaultValue("8") @Positive int maxIdle,
        @DefaultValue("4") @Positive int minIdle,
        @DefaultValue("2s") @DurationUnit(ChronoUnit.SECONDS) Duration maxWait,
        @DefaultValue("30s") @DurationUnit(ChronoUnit.SECONDS) Duration timeBetweenEvictionRuns
    ) {}
  }

  /**
   * Cache configuration for performance optimization
   */
  public record CacheProperties(
      @NotNull @Valid SessionCacheProperties session
  ) {
    public record SessionCacheProperties(
        @DefaultValue("10s") @DurationUnit(ChronoUnit.SECONDS) Duration localTtl,
        @DefaultValue("10000") @Positive int maxSize,
        @DefaultValue("0.5") @DecimalMin("0.1") @DecimalMax("0.9") double refreshThreshold
    ) {}
  }
}
