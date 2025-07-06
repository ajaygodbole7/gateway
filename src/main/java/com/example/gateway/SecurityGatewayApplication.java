package com.example.gateway;

import com.example.gateway.properties.ApplicationProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

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
@EnableConfigurationProperties(ApplicationProperties.class)
@EnableScheduling
public class SecurityGatewayApplication {
  public static void main(String[] args) {
    // Enable virtual threads at JVM level
    System.setProperty("jdk.virtualThreadScheduler.parallelism",
                       String.valueOf(Runtime.getRuntime().availableProcessors()));
    System.setProperty("jdk.virtualThreadScheduler.maxPoolSize", "256");

    SpringApplication app = new SpringApplication(SecurityGatewayApplication.class);

    // Azure-specific optimizations
    app.setLazyInitialization(false); // Faster cold starts
    app.setRegisterShutdownHook(true); // Graceful shutdown for Azure

    app.run(args);
  }
}
