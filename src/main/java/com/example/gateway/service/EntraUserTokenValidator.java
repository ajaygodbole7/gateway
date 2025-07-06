package com.example.gateway.service;

import com.example.gateway.exception.EntraException;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import java.io.IOException;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Validates a USER'S token from Microsoft Entra ID. This implementation uses the common pattern of
 * calling a protected API (like Graph API's /me endpoint) with the user's token to confirm its
 * validity.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EntraUserTokenValidator {

  private static final String ENTRA_VALIDATOR_BREAKER = "microsoftEntra";

  @Qualifier("defaultOkHttpClient")
  private final OkHttpClient httpClient;

  @Value("${app.auth.entra.validation-uri}")
  private String validationUri;

  /**
   * Validates a token by using it as a Bearer token to call a protected Entra endpoint.
   *
   * @param userPlaintextToken The user's Entra ID token.
   * @return Optional containing the same token if active/valid, empty otherwise.
   * @throws EntraException if the validation call fails due to a network or server error.
   */
  @CircuitBreaker(name = ENTRA_VALIDATOR_BREAKER, fallbackMethod = "validationFallback")
  public Optional<String> validateToken(String userPlaintextToken) {
    log.debug("Performing real-time token validation against Microsoft Entra by calling a "
                  + "protected API.");
    Request request = new Request.Builder()
        .url(validationUri)
        .header("Authorization",
                "Bearer " + userPlaintextToken)
        .get()
        .build();

    try (Response response = httpClient.newCall(request).execute()) {
      if (response.isSuccessful()) {
        log.debug("Entra token validation successful (downstream API returned 2xx).");
        return Optional.of(userPlaintextToken);
      }
      else {
        // This indicates the token is invalid (e.g., 401 Unauthorized) or the user lacks
        // permissions (403).
        log.warn("Entra token validation failed with HTTP status: {} for endpoint {}",
                 response.code(),
                 validationUri);
        return Optional.empty();
      }
    } catch (IOException e) {
      log.error("IOException during Entra token validation call.",
                e);
      // This is a system/network failure, not a token validation failure. Let the circuit
      // breaker handle it.
      throw new EntraException("Network error during Entra token validation.",
                               e);
    }
  }

  /**
   * Fallback for the validation circuit breaker.
   *
   * @param userPlaintextToken The token that was being validated.
   * @param t                  The exception that triggered the fallback.
   * @return Always returns an empty Optional to "fail closed" for security.
   */
  private Optional<String> validationFallback(String userPlaintextToken,
                                              Throwable t) {
    log.error("Microsoft Entra validation circuit breaker is OPEN. Failing closed for security. "
                  + "Error: {}",
              t.getMessage());
    return Optional.empty();
  }
}
