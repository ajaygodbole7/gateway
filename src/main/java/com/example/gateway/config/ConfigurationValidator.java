package com.example.gateway.config;

import com.example.gateway.properties.ApplicationProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration validator that enforces business rules and constraints
 * beyond basic JSR-303 validation. Implements fail-fast principle and uses
 * centralized constants to eliminate magic strings.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@EnableConfigurationProperties(ApplicationProperties.class)
public class ConfigurationValidator implements InitializingBean {

  // --- Centralized Constants for Validation and Error Messages ---
  private static final String ERROR_INVALID_URL = "%s is invalid: %s";
  private static final String ERROR_INVALID_URI = "%s is invalid: %s";
  private static final String ERROR_HTTPS_REQUIRED = "%s must use HTTPS in non-local environments: %s";
  private static final String ERROR_MUST_BE_POSITIVE = "%s must be at least 1.";
  private static final String ERROR_MIN_DURATION = "%s must be at least %s.";
  private static final String PROTOCOL_HTTP = "http://";
  private static final String HOST_LOCALHOST = "localhost";
  private static final String HOST_MS_ONLINE = "microsoftonline.com";
  private static final String HOST_AZURE_VAULT = "vault.azure.net";
  private static final String PATH_PREFIX_SLASH = "/";
  private static final String PATH_TRAVERSAL_SEQUENCE = "..";
  private static final String ENTRA_AUDIENCE_SUFFIX_DEFAULT = ".default";
  private static final String URI_PREFIX_PROTOCOL = "://";

  private final ApplicationProperties properties;

  @Override
  public void afterPropertiesSet() {
    log.info("Validating application configuration business rules...");
    List<String> errors = new ArrayList<>();

    validateFrontendConfig(errors);
    validateAuthConfig(errors);
    validateM2mConfig(errors);
    validateSecurityConfig(errors);
    validateHttpConfig(errors);
    validateAzureConfig(errors);

    if (!errors.isEmpty()) {
      String errorMessage = String.format("Configuration validation failed with %d error(s):\n- %s",
                                          errors.size(), String.join("\n- ", errors));
      log.error(errorMessage);
      throw new IllegalStateException(errorMessage);
    }
    log.info("Configuration validation validated successfully.");
  }

  private void validateFrontendConfig(List<String> errors) {
    if (!isValidUrl(properties.frontend().url())) {
      errors.add(ERROR_INVALID_URL.formatted("Frontend URL", properties.frontend().url()));
    }
    validateHttpsRequired(properties.frontend().url(), "Frontend URL", errors);
  }

  private void validateAuthConfig(List<String> errors) {
    validatePingConfig(properties.auth().ping(), errors);
    validateEntraConfig(properties.auth().entra(), errors);

    int codeVerifierLength = properties.auth().codeVerifierLength();
    if (codeVerifierLength < 43 || codeVerifierLength > 128) {
      errors.add("Code verifier length must be between 43-128 characters (RFC 7636), but was: " + codeVerifierLength);
    }

    if (properties.auth().allowedReturnPaths().isEmpty()) {
      errors.add("At least one allowed return path must be configured in 'app.auth.allowed-return-paths'.");
    }
    for (String path : properties.auth().allowedReturnPaths()) {
      if (!path.startsWith(PATH_PREFIX_SLASH)) {
        errors.add("Allowed return path must start with a '/': " + path);
      }
      if (path.contains(PATH_TRAVERSAL_SEQUENCE)) {
        errors.add("Allowed return path cannot contain path traversal sequence '..': " + path);
      }
    }
  }

  private void validatePingConfig(ApplicationProperties.AuthProperties.PingProperties ping, List<String> errors) {
    validateUri(ping.authorizationUri(), "Ping authorization URI", errors);
    validateUri(ping.tokenUri(), "Ping token URI", errors);
    validateUri(ping.validationUri(), "Ping validation URI", errors);
    validateUri(ping.jwksUri(), "Ping JWKS URI", errors);
    validateUri(ping.issuerUri(), "Ping issuer URI", errors);
  }

  private void validateEntraConfig(ApplicationProperties.AuthProperties.EntraProperties entra, List<String> errors) {
    if (!isValidUrl(entra.authority()) || (!entra.authority().contains(HOST_MS_ONLINE) && !entra.authority().contains(HOST_LOCALHOST))) {
      errors.add(ERROR_INVALID_URL.formatted("Entra authority", entra.authority()));
    }
    validateUri(entra.issuerUri(), "Entra issuer URI", errors);
    validateUri(entra.validationUri(), "Entra validation URI", errors);

    if (!entra.gatewayM2mAudience().contains(URI_PREFIX_PROTOCOL) && !entra.gatewayM2mAudience().endsWith(ENTRA_AUDIENCE_SUFFIX_DEFAULT)) {
      errors.add("Entra M2M audience must be a valid URI or end with '.default': " + entra.gatewayM2mAudience());
    }
  }

  private void validateM2mConfig(List<String> errors) {
    if (properties.m2m().refresh().rate().compareTo(Duration.ofSeconds(10)) < 0) {
      errors.add(ERROR_MIN_DURATION.formatted("M2M refresh rate", "10 seconds"));
    }
    if (properties.m2m().refresh().initialDelay().isNegative()) {
      errors.add("M2M initial delay cannot be negative.");
    }
    if (properties.m2m().retry().delay().compareTo(Duration.ofMillis(100)) < 0) {
      errors.add(ERROR_MIN_DURATION.formatted("M2M retry delay", "100ms"));
    }
    long totalRetryTimeMs = (long) properties.m2m().retry().maxAttempts() * properties.m2m().retry().delay().toMillis();
    if (totalRetryTimeMs > 30000) {
      errors.add("Total M2M retry time (%dms) exceeds 30 seconds. Consider reducing attempts or delay.".formatted(totalRetryTimeMs));
    }
  }

  private void validateSecurityConfig(List<String> errors) {
    int slidingWindow = properties.security().session().slidingWindowMinutes();
    int absoluteTimeout = properties.security().session().absoluteTimeoutHours() * 60;
    if (slidingWindow >= absoluteTimeout) {
      errors.add("Sliding window (%d min) must be less than absolute timeout (%d min)".formatted(slidingWindow, absoluteTimeout));
    }
  }

  private void validateHttpConfig(List<String> errors) {
    ApplicationProperties.OkHttpProperties.ClientProperties client = properties.http().client();
    if (client.maxRequests() < client.maxRequestsPerHost()) {
      errors.add("Total max requests must be greater than or equal to max requests per host.");
    }
  }

  private void validateAzureConfig(List<String> errors) {
    String keyVaultUri = properties.azure().keyVault().uri();
    if (!isValidUrl(keyVaultUri) || (!keyVaultUri.contains(HOST_AZURE_VAULT) && !keyVaultUri.contains(HOST_LOCALHOST))) {
      errors.add(ERROR_INVALID_URL.formatted("Azure Key Vault URI", keyVaultUri));
    }
    validateHttpsRequired(keyVaultUri, "Azure Key Vault URI", errors);
  }

  private boolean isValidUrl(String url) {
    try {
      new URL(url);
      return true;
    } catch (MalformedURLException e) {
      return false;
    }
  }

  private void validateUri(String uri, String fieldName, List<String> errors) {
    try {
      new URI(uri);
    } catch (URISyntaxException e) {
      errors.add(ERROR_INVALID_URI.formatted(fieldName, uri));
    }
  }

  private void validateHttpsRequired(String uri, String fieldName, List<String> errors) {
    if (uri != null && uri.startsWith(PROTOCOL_HTTP) && !uri.contains(HOST_LOCALHOST)) {
      errors.add(ERROR_HTTPS_REQUIRED.formatted(fieldName, uri));
    }
  }
}
