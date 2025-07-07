package com.example.gateway.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.boot.convert.DurationUnit;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * A single, centralized, and type-safe record for all application configuration properties.
 */
@Validated
@ConfigurationProperties(prefix = "app")
public record ApplicationProperties(
    @NotNull @Valid FrontendProperties frontend,
    @NotNull @Valid AuthProperties auth,
    @NotNull @Valid M2mProperties m2m,
    @NotNull @Valid SecurityProperties security,
    @NotNull @Valid ApplicationProperties.OkHttpProperties http,
    @NotNull @Valid AzureProperties azure
) {

  public record FrontendProperties(@NotBlank String url) {}

  public record AuthProperties(
      @NotNull @Valid PingProperties ping,
      @NotNull @Valid EntraProperties entra,
      @NotNull List<String> allowedReturnPaths,
      @DefaultValue("64") @Positive int codeVerifierLength
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

  public record M2mProperties(
      @NotNull @Valid RefreshProperties refresh,
      @NotNull @Valid RetryProperties retry
  ) {
    /**
     * Uses java.time.Duration for type-safe and user-friendly configuration.
     * Values in application.yml can be specified as "60s", "1m", "10000ms", etc.
     */
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

  public record SecurityProperties(
      @NotNull @Valid AuthSecurityProperties auth,
      @NotNull @Valid SessionProperties session
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

  public record AzureProperties(@NotNull @Valid KeyVaultProperties keyVault) {
    public record KeyVaultProperties(@NotBlank String uri) {}
  }
}
