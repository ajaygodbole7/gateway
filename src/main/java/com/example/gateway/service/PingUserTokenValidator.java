package com.example.gateway.service;

import com.example.gateway.domain.entity.IdpProvider;
import com.example.gateway.exception.PingIdentityException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import java.io.IOException;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Validates a USER'S token with Ping Identity. This service authenticates itself to the validation
 * endpoint using the Ping M2M token. It is designed to handle Ping's "refresh-on-use" pattern.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PingUserTokenValidator {

  private static final String PING_VALIDATOR_BREAKER = "pingIdentity";

  @Qualifier("defaultOkHttpClient")
  private final OkHttpClient httpClient;
  private final M2MTokenManagerService m2mTokenManagerService;
  private final ObjectMapper objectMapper;

  @Value("${app.auth.ping.validation-uri}")
  private String validationUri;

  /**
   * Synchronously validates a user's token and, if active, returns a new, refreshed ID token.
   *
   * @param userPlaintextToken The user's current ID token to be validated.
   * @return An Optional containing the new (or original) ID token string if validation is
   * successful.
   * @throws PingIdentityException if the validation call fails due to a network or server error.
   */
  @CircuitBreaker(name = PING_VALIDATOR_BREAKER, fallbackMethod = "validationFallback")
  public Optional<String> validateToken(String userPlaintextToken) {
    log.debug("Performing real-time token validation for a user token from Ping Identity.");
    String gatewayM2MToken = m2mTokenManagerService.getAccessToken(IdpProvider.PING_IDENTITY);

    RequestBody formBody = new FormBody.Builder()
        .add("token",
             userPlaintextToken)
        .add("token_type_hint",
             "id_token")
        .build();

    Request request = new Request.Builder()
        .url(validationUri)
        .header("Authorization",
                "Bearer " + gatewayM2MToken)
        .post(formBody)
        .build();

    try (Response response = httpClient.newCall(request).execute()) {
      if (!response.isSuccessful()) {
        log.error("Ping token validation call failed with HTTP status: {}",
                  response.code());
        throw new PingIdentityException(
            "Validation endpoint returned a non-successful status code: " + response.code());
      }

      ResponseBody body = response.body();
      if (body == null) {
        throw new PingIdentityException("Received an empty response body from the Ping validation"
                                            + " endpoint.");
      }

      JsonNode responseNode = objectMapper.readTree(body.string());
      if (responseNode.path("active").asBoolean(false)) {
        String newIdToken = responseNode.path("id_token").asText(null);
        log.debug("Ping token validation successful.");
        // If a new token is returned, use it. Otherwise, reuse the original token for this one
        // request.
        return Optional.ofNullable(newIdToken).or(() -> Optional.of(userPlaintextToken));
      }
      else {
        log.warn("Ping token validation result: user token is INACTIVE.");
        return Optional.empty();
      }
    } catch (IOException e) {
      log.error("IOException during Ping token validation call.",
                e);
      throw new PingIdentityException("A network error occurred during token validation.",
                                      e);
    } catch (Exception e) {
      // Catches parsing exceptions and other unexpected runtime errors
      log.error("An unexpected error occurred while processing the Ping validation response.",
                e);
      throw new PingIdentityException("Could not process response from Ping validation endpoint.",
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
    log.error("Ping Identity validation circuit breaker is OPEN. Failing closed for security. "
                  + "Error: {}",
              t.getMessage());
    return Optional.empty();
  }
}
