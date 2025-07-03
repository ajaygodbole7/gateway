package com.example.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Security Gateway Application
 *
 * OAuth2 authentication gateway for horizontal scaling with:
 * - Azure Key Vault for secrets management
 * - Redis with TLS for session storage
 * - Ping Identity integration
 * - APIM verdict endpoints
 */
@SpringBootApplication
public class SecurityGatewayApplication {
  public static void main(String[] args) {
    SpringApplication.run(SecurityGatewayApplication.class, args);
  }
}
