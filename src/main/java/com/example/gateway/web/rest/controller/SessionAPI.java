package com.example.gateway.web.rest.controller;

import static com.example.gateway.web.rest.ApiConstants.ApiPath.*;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Session management API for React UI.
 * Provides lightweight endpoints for session validation.
 */
@Tag(
    name = "Session Management",
    description = "Session information endpoints for React UI"
)
@RequestMapping(
    value = API_BASE + SESSION,
    produces = MediaType.APPLICATION_JSON_VALUE
)
public interface SessionAPI {

  /**
   * Lightweight session validity check.
   * No authentication filter, no heavy operations.
   */
  @Operation(
      summary = "Check session validity",
      description = "Fast endpoint to check if session is still valid"
  )
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "Session status returned")
  })
  @GetMapping(value = "/check")
  ResponseEntity<Map<String, Object>> checkSession();

  /**
   * Get current user information.
   * Returns cached user data without token decryption.
   */
  @Operation(
      summary = "Get current user",
      description = "Returns the currently authenticated user's profile information"
  )
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "User profile returned"),
      @ApiResponse(responseCode = "401", description = "Not authenticated"),
      @ApiResponse(responseCode = "500", description = "Internal server error")
  })
  @GetMapping(value = ME)
  ResponseEntity<Map<String, Object>> getCurrentUser();

  /**
   * Get detailed session information.
   * Returns user and session metadata.
   */
  @Operation(
      summary = "Get session information",
      description = "Returns detailed session information including user and session metadata"
  )
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "Session information returned"),
      @ApiResponse(responseCode = "401", description = "Not authenticated"),
      @ApiResponse(responseCode = "500", description = "Internal server error")
  })
  @GetMapping(value = INFO)
  ResponseEntity<Map<String, Object>> getSessionInfo();

  ResponseEntity<Map<String, Object>> getCacheStats();
}
