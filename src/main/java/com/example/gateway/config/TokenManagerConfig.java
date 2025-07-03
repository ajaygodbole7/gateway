package com.example.gateway.config;

import com.example.gateway.service.TokenManagerService;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

/**
 * Token Manager Lifecycle Configuration
 */
@Configuration
@RequiredArgsConstructor
public class TokenManagerConfig {

  private final TokenManagerService tokenManagerService;

  @PostConstruct
  public void initialize() {
    tokenManagerService.initialize();
  }

  @PreDestroy
  public void shutdown() {
    tokenManagerService.shutdown();
  }
}
