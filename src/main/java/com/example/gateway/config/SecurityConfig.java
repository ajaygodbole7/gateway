package com.example.gateway.config;

import com.example.gateway.security.filter.SessionAuthenticationFilter;
import com.example.gateway.web.rest.errors.DelegatedAuthenticationEntryPoint;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter.HeaderValue;

/**
 * Lean Gateway Security Configuration - Horizontally Scalable PHILOSOPHY: Stateless security
 * configuration for multi-instance deployment
 * <p>
 * Uses Three separate filter chains PUBLIC CHAIN (@Order(1)): OAuth2 flow Health endpoints for load
 * balancer integration PROTECTED CHAIN (@Order(2)): Session-cookie authenticated endpoints
 * SessionAuthenticationFilter validates distributed sessions DEFAULT CHAIN (@Order(3)): Everything
 * else Explicit deny-all for security by default
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  // Custom filter that checks if user has valid session
  private final SessionAuthenticationFilter sessionAuthenticationFilter;
  // Handles what happens when authentication fails
  private final DelegatedAuthenticationEntryPoint delegatedAuthenticationEntryPoint;

  @Bean
  @Order(1)
  public SecurityFilterChain publicEndpointsFilterChain(HttpSecurity http) throws Exception {
    http
        // Only apply this chain to these specific URLs
        .securityMatcher("/auth/**",
                         "/actuator/**",
                         "/health/**",
                         "/.well-known/**")
        // Allow anyone to access these endpoints
        .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll());

    applyCommonSettings(http);
    return http.build();
  }

  @Bean
  @Order(2)
  //Filter chain #2: Protected API endpoints (authentication required)
  public SecurityFilterChain protectedEndpointsFilterChain(HttpSecurity http) throws Exception {
    http
        .securityMatcher("/api/**",
                         "/internal/**")
        // Add our custom session checker before Spring's default auth filter
        .addFilterBefore(sessionAuthenticationFilter,
                         UsernamePasswordAuthenticationFilter.class)
        // Require authentication for all these endpoints
        .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
        // When auth fails, use our JSON error handler instead of Spring's default HTML
        // This ensures API clients get JSON errors, not HTML login pages
        .exceptionHandling(exceptions ->
                               exceptions.authenticationEntryPoint(delegatedAuthenticationEntryPoint));

    applyCommonSettings(http);
    return http.build();
  }

  @Bean
  @Order(3)
  /**
   * Filter chain #3: Deny everything else (security by default)
   * Catches any URLs not matched by chains #1 or #2
   */
  public SecurityFilterChain defaultDenyFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(authorize -> authorize.anyRequest().denyAll());
    applyCommonSettings(http);
    return http.build();
  }

  /**
   * Common security settings applied to all chains These protect against common web
   * vulnerabilities
   */
  private void applyCommonSettings(HttpSecurity http) throws Exception {
    http
        // Disable CSRF since we use session cookies with HttpOnly flag
        .csrf(AbstractHttpConfigurer::disable)

        // Don't create server sessions - we manage sessions in Redis
        .sessionManagement(session -> session
                               .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                          )

        // Security headers to protect against attacks
        .headers(headers -> headers
                     // Prevents page from being shown in iframe (stops clickjacking)
                     .frameOptions(FrameOptionsConfig::deny)

                     // Enables browser's XSS protection
                     .xssProtection(xss -> xss
                                        .headerValue(HeaderValue.ENABLED_MODE_BLOCK)
                                   )

                     // Prevents browser from guessing content type
                     .contentTypeOptions(contentType -> {
                     })

                     // Controls what info is sent when user navigates away
                     .referrerPolicy(referrer -> referrer
                                         .policy(ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                                    )
                     // Disables browser features we don't need (camera, microphone, etc)
                     .permissionsPolicyHeader(permissions -> permissions
                                                  .policy("camera=(), microphone="
                                                              + "(), geolocation="
                                                              + "(), payment=()")
                                             )

                     // Forces HTTPS for 1 year (only works after first HTTPS visit)
                     .httpStrictTransportSecurity(hsts -> hsts
                                                      .maxAgeInSeconds(Duration.ofDays(365).toSeconds())
                                                      .includeSubDomains(true)
                                                      .preload(true)
                                                  // Request inclusion in browser HSTS lists
                                                 )

                     // Controls what resources the page can load
                     .contentSecurityPolicy(csp -> csp
                                                .policyDirectives(
                                                    "default-src 'self'; " +              // Only
                                                        // load resources from our domain
                                                        "script-src 'self'; " +               //
                                                        // Only our JavaScript
                                                        "style-src 'self' 'unsafe-inline'; " + //
                                                        // Our CSS + inline styles
                                                        "img-src 'self' data: https:; " +
                                                        // Images from our domain, data URLs, any
                                                        // HTTPS
                                                        "font-src 'self'; " +                 //
                                                        // Only our fonts
                                                        "connect-src 'self'; " +              //
                                                        // AJAX/WebSocket only to our domain
                                                        "frame-ancestors 'none'; " +          //
                                                        // Don't allow embedding in iframes
                                                        "form-action 'self'; " +              //
                                                        // Forms can only submit to our domain
                                                        "base-uri 'self'"
                                                    // <base> tag can only point to our domain
                                                                 )
                                           )

                     // Add custom headers for caching and OAuth2
                     .addHeaderWriter((request, response) -> {
                       // Tell clients that PKCE is required for OAuth2
                       response.setHeader("X-OAuth2-Security",
                                          "pkce-required");

                       // Prevent browser from caching sensitive data
                       response.setHeader("Cache-Control",
                                          "no-cache, no-store, must-revalidate");
                       response.setHeader("Pragma",
                                          "no-cache");
                       response.setHeader("Expires",
                                          "0");
                     })
                );
  }
}
