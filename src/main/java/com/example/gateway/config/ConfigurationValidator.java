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
 * beyond basic JSR-303 validation. Implements fail-fast principle.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@EnableConfigurationProperties(ApplicationProperties.class)
public class ConfigurationValidator implements InitializingBean {

  private final ApplicationProperties properties;

  @Override
  public void afterPropertiesSet() throws Exception {
    log.info("Validating application configuration...");

    List<String> errors = new ArrayList<>();

    // Validate Frontend Configuration
    validateFrontendConfig(errors);

    // Validate Authentication Configuration
    validateAuthConfig(errors);

    // Validate M2M Configuration
    validateM2mConfig(errors);

    // Validate Security Configuration
    validateSecurityConfig(errors);

    // Validate HTTP Client Configuration
    validateHttpConfig(errors);

    // Validate Azure Configuration
    validateAzureConfig(errors);

    // Cross-configuration validations
    validateCrossConfiguration(errors);

    // Fail fast if any errors
    if (!errors.isEmpty()) {
      String errorMessage = String.format(
          "Configuration validation failed with %d error(s):\n%s",
          errors.size(),
          String.join("\n", errors)
                                         );
      log.error(errorMessage);
      throw new IllegalStateException(errorMessage);
    }

    log.info("Configuration validation completed successfully");
  }

  private void validateFrontendConfig(List<String> errors) {
    // Validate frontend URL
    if (!isValidUrl(properties.frontend().url())) {
      errors.add("Frontend URL is invalid: " + properties.frontend().url());
    }

    // Ensure HTTPS in production
    if (properties.frontend().url().startsWith("http://") &&
        !properties.frontend().url().contains("localhost")) {
      errors.add("Frontend URL must use HTTPS in non-local environments");
    }
  }

  private void validateAuthConfig(List<String> errors) {
    // Validate Ping configuration
    validatePingConfig(properties.auth().ping(), errors);

    // Validate Entra configuration
    validateEntraConfig(properties.auth().entra(), errors);

    // Validate PKCE code verifier length (RFC 7636: 43-128 characters)
    int codeVerifierLength = properties.auth().codeVerifierLength();
    if (codeVerifierLength < 43 || codeVerifierLength > 128) {
      errors.add(String.format(
          "Code verifier length must be between 43-128 characters (RFC 7636), got: %d",
          codeVerifierLength
                              ));
    }

    // Validate allowed return paths
    if (properties.auth().allowedReturnPaths().isEmpty()) {
      errors.add("At least one allowed return path must be configured");
    }

    for (String path : properties.auth().allowedReturnPaths()) {
      if (!path.startsWith("/")) {
        errors.add("Allowed return path must start with '/': " + path);
      }
      if (path.contains("..")) {
        errors.add("Allowed return path contains path traversal: " + path);
      }
    }
  }

  private void validatePingConfig(ApplicationProperties.AuthProperties.PingProperties ping,
                                  List<String> errors) {
    // Validate URIs
    if (!isValidUri(ping.authorizationUri())) {
      errors.add("Ping authorization URI is invalid: " + ping.authorizationUri());
    }

    if (!isValidUri(ping.tokenUri())) {
      errors.add("Ping token URI is invalid: " + ping.tokenUri());
    }

    if (!isValidUri(ping.validationUri())) {
      errors.add("Ping validation URI is invalid: " + ping.validationUri());
    }

    if (!isValidUri(ping.jwksUri())) {
      errors.add("Ping JWKS URI is invalid: " + ping.jwksUri());
    }

    if (!isValidUri(ping.issuerUri())) {
      errors.add("Ping issuer URI is invalid: " + ping.issuerUri());
    }

    // Ensure all URIs use HTTPS
    validateHttpsRequired(ping.authorizationUri(), "Ping authorization URI", errors);
    validateHttpsRequired(ping.tokenUri(), "Ping token URI", errors);
    validateHttpsRequired(ping.validationUri(), "Ping validation URI", errors);
    validateHttpsRequired(ping.jwksUri(), "Ping JWKS URI", errors);
  }

  private void validateEntraConfig(ApplicationProperties.AuthProperties.EntraProperties entra,
                                   List<String> errors) {
    // Validate authority format
    if (!isValidUrl(entra.authority())) {
      errors.add("Entra authority is invalid: " + entra.authority());
    }

    if (!entra.authority().contains("microsoftonline.com") &&
        !entra.authority().contains("localhost")) {
      errors.add("Entra authority must be a valid Microsoft authority URL");
    }

    // Validate issuer URI
    if (!isValidUri(entra.issuerUri())) {
      errors.add("Entra issuer URI is invalid: " + entra.issuerUri());
    }

    // Validate validation URI
    if (!isValidUri(entra.validationUri())) {
      errors.add("Entra validation URI is invalid: " + entra.validationUri());
    }

    // Validate M2M audience
    if (!entra.gatewayM2mAudience().contains("://") &&
        !entra.gatewayM2mAudience().endsWith(".default")) {
      errors.add("Entra M2M audience must be a valid URI or end with .default");
    }
  }

  private void validateM2mConfig(List<String> errors) {
    // Validate refresh rate
    try {
      long refreshRate = Long.parseLong(properties.m2m().refresh().rate());
      if (refreshRate < 10000) { // Less than 10 seconds
        errors.add("M2M refresh rate must be at least 10 seconds, got: " + refreshRate + "ms");
      }
    } catch (NumberFormatException e) {
      errors.add("M2M refresh rate must be a valid number: " + properties.m2m().refresh().rate());
    }

    // Validate initial delay
    try {
      long initialDelay = Long.parseLong(properties.m2m().refresh().initialDelay());
      if (initialDelay < 0) {
        errors.add("M2M initial delay cannot be negative");
      }
    } catch (NumberFormatException e) {
      errors.add("M2M initial delay must be a valid number: " + properties.m2m().refresh().initialDelay());
    }

    // Validate retry configuration
    if (properties.m2m().retry().maxAttempts() < 1) {
      errors.add("M2M retry max attempts must be at least 1");
    }

    if (properties.m2m().retry().delayMs() < 100) {
      errors.add("M2M retry delay must be at least 100ms to prevent tight loops");
    }

    // Check total retry time doesn't exceed reasonable limits
    long totalRetryTime = properties.m2m().retry().maxAttempts() * properties.m2m().retry().delayMs();
    if (totalRetryTime > 30000) { // 30 seconds
      errors.add(String.format(
          "Total M2M retry time (%dms) exceeds 30 seconds. Consider reducing attempts or delay.",
          totalRetryTime
                              ));
    }
  }

  private void validateSecurityConfig(List<String> errors) {
    // Validate auth security
    if (properties.security().auth().maxFailures() < 1) {
      errors.add("Max authentication failures must be at least 1");
    }

    if (properties.security().auth().blockDurationMinutes() < 1) {
      errors.add("Block duration must be at least 1 minute");
    }

    // Validate session configuration
    int slidingWindow = properties.security().session().slidingWindowMinutes();
    int absoluteTimeout = properties.security().session().absoluteTimeoutHours() * 60;

    if (slidingWindow >= absoluteTimeout) {
      errors.add(String.format(
          "Sliding window (%d min) must be less than absolute timeout (%d min)",
          slidingWindow, absoluteTimeout
                              ));
    }

    if (slidingWindow < 5) {
      errors.add("Sliding window should be at least 5 minutes for usability");
    }

    if (absoluteTimeout > 1440) { // 24 hours
      errors.add("Absolute timeout should not exceed 24 hours for security");
    }
  }

  private void validateHttpConfig(List<String> errors) {
    ApplicationProperties.HttpProperties.ClientProperties client = properties.http().client();

    if (client.maxIdleConnections() < 1) {
      errors.add("Max idle connections must be at least 1");
    }

    if (client.keepAliveDurationMinutes() < 1) {
      errors.add("Keep alive duration must be at least 1 minute");
    }

    if (client.maxRequests() < client.maxRequestsPerHost()) {
      errors.add("Total max requests must be >= max requests per host");
    }

    if (client.maxRequestsPerHost() < 1) {
      errors.add("Max requests per host must be at least 1");
    }
  }

  private void validateAzureConfig(List<String> errors) {
    String keyVaultUri = properties.azure().keyVault().uri();

    if (!isValidUrl(keyVaultUri)) {
      errors.add("Azure Key Vault URI is invalid: " + keyVaultUri);
    }

    if (!keyVaultUri.contains("vault.azure.net") && !keyVaultUri.contains("localhost")) {
      errors.add("Key Vault URI must be a valid Azure Key Vault endpoint");
    }

    validateHttpsRequired(keyVaultUri, "Key Vault URI", errors);
  }

  private void validateCrossConfiguration(List<String> errors) {
    // Ensure M2M refresh rate is less than token lifetime
    try {
      long refreshRate = Long.parseLong(properties.m2m().refresh().rate());
      // M2M tokens typically last 1 hour, refresh should happen well before
      if (refreshRate > 3000000) { // 50 minutes
        errors.add("M2M refresh rate should be less than 50 minutes to ensure tokens don't expire");
      }
    } catch (NumberFormatException e) {
      // Already caught in M2M validation
    }

    // Validate that all configured IdPs have matching client IDs
    if (properties.auth().ping().clientId().equals(properties.auth().entra().clientId())) {
      log.warn("Ping and Entra are using the same client ID - this may be unintended");
    }
  }

  private boolean isValidUrl(String url) {
    try {
      new URL(url);
      return true;
    } catch (MalformedURLException e) {
      return false;
    }
  }

  private boolean isValidUri(String uri) {
    try {
      new URI(uri);
      return true;
    } catch (URISyntaxException e) {
      return false;
    }
  }

  private void validateHttpsRequired(String uri, String fieldName, List<String> errors) {
    if (uri.startsWith("http://") && !uri.contains("localhost")) {
      errors.add(fieldName + " must use HTTPS in non-local environments: " + uri);
    }
  }
}
