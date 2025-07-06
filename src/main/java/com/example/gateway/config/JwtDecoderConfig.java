package com.example.gateway.config;



import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;

import java.util.List;

@Configuration(proxyBeanMethods = false)
public class JwtDecoderConfig {

  @Value("${app.auth.ping.jwks-uri}")
  private String jwksUri;

  @Value("${app.auth.ping.issuer-uri}")
  private String issuerUri;

  @Value("${app.auth.ping.expected-audience}")
  private String expectedAudience;

  @Value("${app.auth.ping.expected-azp}")
  private String expectedAzp;

  @Bean
  @Profile("!test")
  public JwtDecoder jwtDecoder() {
    NimbusJwtDecoder decoder = NimbusJwtDecoder
        .withJwkSetUri(jwksUri)
        .jwsAlgorithm(SignatureAlgorithm.RS256)
        .build();

    // Compose multiple validators
    OAuth2TokenValidator<Jwt> issuerValidator =
        JwtValidators.createDefaultWithIssuer(issuerUri);

    OAuth2TokenValidator<Jwt> audienceValidator = jwt -> {
      List<String> aud = jwt.getAudience();
      return (aud != null && aud.contains(expectedAudience))
          ? OAuth2TokenValidatorResult.success()
          : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Invalid audience", null));
    };

    OAuth2TokenValidator<Jwt> azpValidator = jwt -> {
      String azp = jwt.getClaim("azp");
      return (azp != null && azp.equals(expectedAzp))
          ? OAuth2TokenValidatorResult.success()
          : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Invalid azp", null));
    };

    OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(
        issuerValidator,
        audienceValidator,
        azpValidator
    );

    decoder.setJwtValidator(validator);

    return decoder;
  }
}

