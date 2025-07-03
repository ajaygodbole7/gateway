package com.example.gateway.web.rest.controller;

import static com.example.gateway.web.rest.ApiConstants.ApiPath.*;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Tag(
    name = "Authentication",
    description = "OAuth2 authentication endpoints for user login and session management"
)
@RequestMapping(
    value = AUTH_BASE,
    produces = MediaType.APPLICATION_JSON_VALUE
)
public interface AuthAPI {

  @Operation(
      summary = "Initiate OAuth2 login flow",
      description = "Starts the OAuth2 + PKCE authentication flow with Ping Identity"
  )
  @ApiResponses(value = {
      @ApiResponse(responseCode = "302", description = "Redirect to identity provider"),
      @ApiResponse(responseCode = "429", description = "Too many failed attempts"),
      @ApiResponse(responseCode = "500", description = "Internal server error")
  })
  @GetMapping(value = LOGIN)
  ResponseEntity<?> login(
      @Parameter(description = "Return URL after successful login", example = "/dashboard")
      @RequestParam(defaultValue = "/dashboard") String returnTo,
      HttpServletRequest request
                         );

  @Operation(
      summary = "OAuth2 callback handler",
      description = "Handles the OAuth2 callback from Ping Identity after user authentication"
  )
  @ApiResponses(value = {
      @ApiResponse(responseCode = "302", description = "Redirect to application with session"),
      @ApiResponse(responseCode = "400", description = "Invalid callback parameters"),
      @ApiResponse(responseCode = "429", description = "Too many failed attempts"),
      @ApiResponse(responseCode = "500", description = "Authentication failed")
  })
  @GetMapping(value = CALLBACK)
  ResponseEntity<?> callback(
      @Parameter(description = "Authorization code", required = true)
      @RequestParam String code,
      @Parameter(description = "State parameter for CSRF protection", required = true)
      @RequestParam String state,
      HttpServletRequest request,
      HttpServletResponse response
                            );

  @Operation(
      summary = "Logout user",
      description = "Invalidates the user session and clears session cookie"
  )
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "Successfully logged out"),
      @ApiResponse(responseCode = "500", description = "Internal server error")
  })
  @PostMapping(value = LOGOUT)
  ResponseEntity<?> logout(
      @Parameter(description = "Session cookie", required = false)
      @CookieValue(value = "app_session", required = false) String sessionId,
      HttpServletResponse response
                          );

  @Operation(
      summary = "Refresh session",
      description = "Extends the session lifetime if still valid"
  )
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "Session refreshed successfully"),
      @ApiResponse(responseCode = "401", description = "Session invalid or expired"),
      @ApiResponse(responseCode = "500", description = "Internal server error")
  })
  @PostMapping(value = REFRESH)
  ResponseEntity<?> refresh(
      @Parameter(description = "Session cookie", required = false)
      @CookieValue(value = "app_session", required = false) String sessionId,
      HttpServletRequest request
                           );

  @Operation(
      summary = "Check authentication status",
      description = "Returns whether the user has a valid session"
  )
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "Authentication status returned"),
      @ApiResponse(responseCode = "500", description = "Internal server error")
  })
  @GetMapping(value = STATUS)
  ResponseEntity<Map<String, Object>> status(
      @Parameter(description = "Session cookie", required = false)
      @CookieValue(value = "app_session", required = false) String sessionId
                                            );
}
