package com.example.gateway.config;

import com.example.gateway.security.filter.SessionAuthenticationFilter;
import com.example.gateway.web.rest.errors.DelegatedAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

import java.time.Duration;

/**
 * Lean Gateway Security Configuration - Horizontally Scalable
 * DESIGN PHILOSOPHY: Stateless security configuration for multi-instance deployment
 * ARCHITECTURE DECISION: Three separate filter chains for optimal performance
 * PUBLIC CHAIN (@Order(1)): OAuth2 flow and health monitoring
 *  Includes health endpoints for load balancer integration
 *  PROTECTED CHAIN (@Order(2)): Session-authenticated endpoints
 *  SessionAuthenticationFilter validates distributed sessions
 *  Works across all gateway instances via Redis
 *  DEFAULT CHAIN (@Order(3)): Everything else
 *  Explicit deny-all for security by default
  */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final SessionAuthenticationFilter sessionAuthenticationFilter;
  private final DelegatedAuthenticationEntryPoint delegatedAuthenticationEntryPoint;

  @Bean
  @Order(1)
  public SecurityFilterChain publicEndpointsFilterChain(HttpSecurity http) throws Exception {
    http
        .securityMatcher("/auth/**", "/actuator/**", "/health/**", "/.well-known/**")
        .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll());

    applyCommonSettings(http);
    return http.build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain protectedEndpointsFilterChain(HttpSecurity http) throws Exception {
    http
        .securityMatcher("/api/**", "/internal/**")
        .addFilterBefore(sessionAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
        .exceptionHandling(exceptions ->
                               exceptions.authenticationEntryPoint(delegatedAuthenticationEntryPoint));

    applyCommonSettings(http);
    return http.build();
  }

  @Bean
  @Order(3)
  public SecurityFilterChain defaultDenyFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(authorize -> authorize.anyRequest().denyAll());
    applyCommonSettings(http);
    return http.build();
  }

  /**
   * Enhanced common settings with PKCE protection
   */
  private void applyCommonSettings(HttpSecurity http) throws Exception {
    http
        .csrf(AbstractHttpConfigurer::disable)
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .headers(headers ->
                     headers
                         // Prevent clickjacking
                         .frameOptions(frameOptions -> frameOptions.deny())
                         // Referrer policy
                         .referrerPolicy(referrer ->
                                             referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                         // Permissions policy
                         .permissionsPolicy(permissions ->
                                                permissions.policy("camera=(), microphone=(), geolocation=(), payment=()"))
                         // HSTS
                         .httpStrictTransportSecurity(hsts ->
                                                          hsts.maxAgeInSeconds(Duration.ofDays(365).toSeconds())
                                                              .includeSubDomains(true)
                                                              .preload(true))
                         // CSP
                         .contentSecurityPolicy(csp ->
                                                    csp.policyDirectives("default-src 'self'; " +
                                                                             "script-src 'self'; " +
                                                                             "style-src 'self' 'unsafe-inline'; " +
                                                                             "img-src 'self' data: https:; " +
                                                                             "font-src 'self'; " +
                                                                             "connect-src 'self'; " +
                                                                             "frame-ancestors 'none'; " +
                                                                             "form-action 'self'; " +
                                                                             "base-uri 'self'"))
                         // Additional security headers
                         .xssProtection(xss -> xss.headerValue("1; mode=block"))
                         .contentTypeOptions(contentType -> {})
                         // Custom headers for OAuth2 security
                         .addHeaderWriter((request, response) -> {
                           response.setHeader("X-OAuth2-Security", "pkce-required");
                           response.setHeader("X-Content-Type-Options", "nosniff");
                           response.setHeader("X-XSS-Protection", "1; mode=block");
                           response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
                           response.setHeader("Pragma", "no-cache");
                           response.setHeader("Expires", "0");
                         })
                );
  }
}
