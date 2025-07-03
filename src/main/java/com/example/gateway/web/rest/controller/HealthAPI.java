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

@Tag(
    name = "Health",
    description = "Health check endpoints for monitoring and orchestration"
)
@RequestMapping(
    value = HEALTH_BASE,
    produces = MediaType.APPLICATION_JSON_VALUE
)
public interface HealthAPI {

  @Operation(
      summary = "Basic health check",
      description = "Simple health check for load balancers"
  )
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "Service is healthy"),
      @ApiResponse(responseCode = "500", description = "Internal server error")
  })
  @GetMapping
  ResponseEntity<Map<String, Object>> health();

  @Operation(
      summary = "Liveness probe",
      description = "Kubernetes liveness probe to determine if the container should be restarted"
  )
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "Service is alive"),
      @ApiResponse(responseCode = "503", description = "Service should be restarted"),
      @ApiResponse(responseCode = "500", description = "Internal server error")
  })
  @GetMapping(value = LIVE)
  ResponseEntity<Map<String, Object>> liveness();

  @Operation(
      summary = "Readiness probe",
      description = "Kubernetes readiness probe to determine if the container can accept traffic"
  )
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "Service is ready"),
      @ApiResponse(responseCode = "503", description = "Service is not ready"),
      @ApiResponse(responseCode = "500", description = "Internal server error")
  })
  @GetMapping(value = READY)
  ResponseEntity<Map<String, Object>> readiness();
}
