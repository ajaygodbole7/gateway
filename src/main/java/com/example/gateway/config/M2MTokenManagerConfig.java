package com.example.gateway.config;

import com.example.gateway.service.M2MTokenManagerService;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

/**
 * Token Manager Lifecycle Configuration
 */
@Configuration
@RequiredArgsConstructor
public class M2MTokenManagerConfig {

  private final M2MTokenManagerService m2MTokenManagerService;

  @PostConstruct
  public void initialize() {
    m2MTokenManagerService.initialize();
  }

  @PreDestroy
  public void shutdown() {
    m2MTokenManagerService.shutdown();
  }
}
