package com.example.gateway.util;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Utility class for JWT validation using Spring's JWT decoder.
 * Handles all OIDC token validation including audience, nonce, and multi-audience claims.
 */
@Slf4j
@UtilityClass
public class JwtValidationUtils {

    // Cache decoders to avoid recreating them
    private static final Map<String, NimbusJwtDecoder> DECODER_CACHE = new HashMap<>();

    /**
     * Validates an ID token with comprehensive OIDC checks.
     *
     * @param idToken The ID token to validate
     * @param jwksUri The JWKS URI for the IdP
     * @param expectedIssuer The expected issuer
     * @param expectedClientId The expected client ID (audience)
     * @param expectedNonce The expected nonce
     * @return The validated JWT
     * @throws OAuth2AuthenticationException if validation fails
     */
    public static Jwt validateIdToken(String idToken, String jwksUri, String expectedIssuer,
                                      String expectedClientId, String expectedNonce) {
        try {
            // Get or create decoder
            NimbusJwtDecoder decoder = DECODER_CACHE.computeIfAbsent(jwksUri, uri -> {
                NimbusJwtDecoder d = NimbusJwtDecoder.withJwkSetUri(uri).build();
                d.setJwtValidator(JwtValidators.createDefaultWithIssuer(expectedIssuer));
                return d;
            });

            // Decode and validate (checks signature, exp, nbf, iat, iss)
            Jwt jwt = decoder.decode(idToken);

            // Validate audience
            List<String> audiences = jwt.getAudience();
            if (audiences == null || !audiences.contains(expectedClientId)) {
                throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_audience",
                                    "Token audience does not include client_id: " + expectedClientId, null)
                );
            }

            // Validate azp for multi-audience tokens
            if (audiences.size() > 1) {
                String azp = jwt.getClaimAsString("azp");
                if (!expectedClientId.equals(azp)) {
                    throw new OAuth2AuthenticationException(
                        new OAuth2Error("invalid_azp",
                                        "Invalid authorized party (azp) for multi-audience token", null)
                    );
                }
            }

            // Validate nonce
            String nonce = jwt.getClaimAsString("nonce");
            if (expectedNonce != null && !expectedNonce.equals(nonce)) {
                throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_nonce",
                                    "Nonce mismatch - possible replay attack", null)
                );
            }

            // Validate at_hash if present (optional validation)
            String atHash = jwt.getClaimAsString("at_hash");
            if (atHash != null) {
                log.debug("at_hash present in token but not validated (access token not available)");
            }

            return jwt;

        } catch (JwtException e) {
            log.error("JWT validation failed: {}", e.getMessage());
            throw new OAuth2AuthenticationException(
                new OAuth2Error("invalid_token", "Token validation failed: " + e.getMessage(), null)
            );
        }
    }
}
