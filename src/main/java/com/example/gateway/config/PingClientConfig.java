package com.example.gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

/**
 * OAuth2 Client Registration Configuration
 */
@Configuration(proxyBeanMethods = false)
public class PingClientConfig {

  @Value("${app.auth.ping.client-id}")
  private String clientId;

  @Value("${app.auth.ping.authorization-uri}")
  private String authorizationUri;

  @Value("${app.auth.ping.token-uri}")
  private String tokenUri;

  @Value("${app.auth.ping.jwks-uri}")
  private String jwksUri;

  @Value("${app.auth.ping.issuer-uri}")
  private String issuerUri;

  @Value("${app.frontend.url}")
  private String frontendUrl;

  @Bean
  public ClientRegistration pingIdentityClientRegistration() {
    return ClientRegistration.withRegistrationId("ping")
        .clientId(clientId)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri(frontendUrl + "/auth/callback")
        .scope("openid", "profile", "email")
        .authorizationUri(authorizationUri)
        .tokenUri(tokenUri)
        .jwkSetUri(jwksUri)
        .issuerUri(issuerUri)
        .userNameAttributeName("preferred_username")
        .clientName("Ping Identity")
        .build();
  }
}
