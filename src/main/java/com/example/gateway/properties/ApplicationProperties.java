package com.example.gateway.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import java.util.List;

/**
 * A single, centralized, and type-safe record for all application configuration properties.
 *
 * @param frontend Configuration for the frontend application URL.
 * @param auth     Configuration for all authentication providers (Ping, Entra).
 * @param m2m      Configuration for the M2M token manager service.
 * @param security Configuration for security features like session timeouts.
 * @param http     Configuration for the underlying HTTP clients.
 * @param azure    Configuration for Azure service integrations.
 */
@Validated
@ConfigurationProperties(prefix = "app")
public record ApplicationProperties(
    @NotNull @Valid FrontendProperties frontend,
    @NotNull @Valid AuthProperties auth,
    @NotNull @Valid M2mProperties m2m,
    @NotNull @Valid SecurityProperties security,
    @NotNull @Valid HttpProperties http,
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
        @NotBlank String tokenUri, // Used for both user and M2M tokens
        @NotBlank String validationUri,
        @NotBlank String jwksUri,
        @NotBlank String issuerUri
    ) {}

    public record EntraProperties(
        @NotBlank String authority,
        @NotBlank String clientId,
        @NotBlank String issuerUri,
        @NotBlank String validationUri,
        @NotBlank String gatewayM2mAudience // Scope for the gateway's own M2M token
    ) {}
  }

  public record M2mProperties(
      @NotNull @Valid RefreshProperties refresh,
      @NotNull @Valid RetryProperties retry
  ) {
    public record RefreshProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("60000") String rate,
        @DefaultValue("60000") String initialDelay
    ) {}

    public record RetryProperties(
        @DefaultValue("15") int maxAttempts,
        @DefaultValue("300") long delayMs
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

  public record HttpProperties(
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
