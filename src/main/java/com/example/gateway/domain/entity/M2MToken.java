package com.example.gateway.domain.entity;

import java.time.Duration;
import java.time.Instant;

/**
 * A simple, immutable record to hold information about a cached M2M token.
 * It encapsulates the JWT token string and its expiration details.
 */
public record M2MToken(

     //The type of the token, for logging and differentiation purposes (e.g., "PING_IDENTITY_M2M").

    IdpProvider tokenProvider,

     // The actual Bearer token string.
     String accessToken,

     // The absolute timestamp at which this token expires.
     Instant expiresAt

) {
  /**
   * Checks if the token is currently expired.
   *
   * @return {@code true} if the current time is after the expiration time, {@code false} otherwise.
   */
  public boolean isExpired() {
    return Instant.now().isAfter(expiresAt);
  }

  /**
   * Checks if the token will expire within a given duration from now.
   * This is useful for proactive refreshing.
   *
   * @param duration The threshold duration to check against.
   * @return {@code true} if the token will expire within the specified duration, {@code false} otherwise.
   */
  public boolean expiresWithin(Duration duration) {
    return Instant.now().plus(duration).isAfter(expiresAt);
  }

  /**
   * Calculates the remaining lifetime of the token.
   *
   * @return A {@code Duration} representing the time until expiration. Returns {@code Duration.ZERO} if the token is already expired.
   */
  public Duration remainingLifetime() {
    Duration remaining = Duration.between(Instant.now(), expiresAt);
    return remaining.isNegative() ? Duration.ZERO : remaining;
  }

  /**
   * A convenient factory method to create a M2MToken instance from an "expires_in" value in seconds.
   *
   * @param tokenProvider The type of the token.
   * @param accessToken The token string.
   * @param expiresInSeconds The number of seconds from now until the token expires.
   * @return A new, fully constructed {@code TokenInfo} object.
   */
  public static M2MToken withExpiresIn(IdpProvider tokenProvider, String accessToken, long expiresInSeconds) {
    return new M2MToken(tokenProvider, accessToken, Instant.now().plusSeconds(expiresInSeconds));
  }
}
