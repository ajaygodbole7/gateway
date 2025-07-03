package com.example.gateway.web.rest.errors;

import com.example.gateway.exception.*;
import jakarta.websocket.SessionException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Global Error Handler
 *
 * Provides consistent error responses without exposing sensitive information
 */
@Slf4j
@RestControllerAdvice
public class GlobalErrorHandler {

  @ExceptionHandler(OAuth2AuthenticationException.class)
  public ResponseEntity<Map<String, Object>> handleOAuth2Exception(
      OAuth2AuthenticationException ex, WebRequest request) {
    log.error("OAuth2 authentication error: {}", ex.getError().getErrorCode(), ex);

    Map<String, Object> body = createErrorBody(
        HttpStatus.UNAUTHORIZED,
        ex.getError().getErrorCode(),
        ex.getError().getDescription(),
        request
                                              );

    return new ResponseEntity<>(body, HttpStatus.UNAUTHORIZED);
  }

  @ExceptionHandler(OAuth2Exception.class)
  public ResponseEntity<Map<String, Object>> handleOAuth2Exception(
      OAuth2Exception ex, WebRequest request) {
    log.error("OAuth2 error", ex);

    Map<String, Object> body = createErrorBody(
        HttpStatus.BAD_REQUEST,
        "invalid_request",
        ex.getMessage(),
        request
                                              );

    return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(SessionException.class)
  public ResponseEntity<Map<String, Object>> handleSessionException(
      SessionException ex, WebRequest request) {
    log.error("Session error", ex);

    Map<String, Object> body = createErrorBody(
        HttpStatus.UNAUTHORIZED,
        "invalid_session",
        "Session is invalid or expired",
        request
                                              );

    return new ResponseEntity<>(body, HttpStatus.UNAUTHORIZED);
  }

  @ExceptionHandler(KeyVaultException.class)
  public ResponseEntity<Map<String, Object>> handleKeyVaultException(
      KeyVaultException ex, WebRequest request) {
    log.error("Key Vault error", ex);

    Map<String, Object> body = createErrorBody(
        HttpStatus.SERVICE_UNAVAILABLE,
        "service_unavailable",
        "Service temporarily unavailable",
        request
                                              );

    return new ResponseEntity<>(body, HttpStatus.SERVICE_UNAVAILABLE);
  }

  @ExceptionHandler(EncryptionException.class)
  public ResponseEntity<Map<String, Object>> handleEncryptionException(
      EncryptionException ex, WebRequest request) {
    log.error("Encryption error", ex);

    Map<String, Object> body = createErrorBody(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "encryption_error",
        "An error occurred processing your request",
        request
                                              );

    return new ResponseEntity<>(body, HttpStatus.INTERNAL_SERVER_ERROR);
  }

  @ExceptionHandler(AuthenticationException.class)
  public ResponseEntity<Map<String, Object>> handleAuthenticationException(
      AuthenticationException ex, WebRequest request) {
    log.error("Authentication error", ex);

    Map<String, Object> body = createErrorBody(
        HttpStatus.UNAUTHORIZED,
        "authentication_failed",
        "Authentication failed",
        request
                                              );

    return new ResponseEntity<>(body, HttpStatus.UNAUTHORIZED);
  }

  @ExceptionHandler(AccessDeniedException.class)
  public ResponseEntity<Map<String, Object>> handleAccessDeniedException(
      AccessDeniedException ex, WebRequest request) {
    log.error("Access denied", ex);

    Map<String, Object> body = createErrorBody(
        HttpStatus.FORBIDDEN,
        "access_denied",
        "Access denied",
        request
                                              );

    return new ResponseEntity<>(body, HttpStatus.FORBIDDEN);
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<Map<String, Object>> handleValidationException(
      MethodArgumentNotValidException ex, WebRequest request) {

    String errors = ex.getBindingResult().getFieldErrors().stream()
        .map(FieldError::getDefaultMessage)
        .collect(Collectors.joining(", "));

    Map<String, Object> body = createErrorBody(
        HttpStatus.BAD_REQUEST,
        "validation_error",
        errors,
        request
                                              );

    return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(MissingServletRequestParameterException.class)
  public ResponseEntity<Map<String, Object>> handleMissingParams(
      MissingServletRequestParameterException ex, WebRequest request) {

    Map<String, Object> body = createErrorBody(
        HttpStatus.BAD_REQUEST,
        "missing_parameter",
        String.format("Missing required parameter: %s", ex.getParameterName()),
        request
                                              );

    return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
  public ResponseEntity<Map<String, Object>> handleMethodNotSupported(
      HttpRequestMethodNotSupportedException ex, WebRequest request) {

    Map<String, Object> body = createErrorBody(
        HttpStatus.METHOD_NOT_ALLOWED,
        "method_not_allowed",
        String.format("Method %s not supported", ex.getMethod()),
        request
                                              );

    return new ResponseEntity<>(body, HttpStatus.METHOD_NOT_ALLOWED);
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<Map<String, Object>> handleGenericException(
      Exception ex, WebRequest request) {
    log.error("Unexpected error", ex);

    Map<String, Object> body = createErrorBody(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "internal_error",
        "An error occurred processing your request",
        request
                                              );

    return new ResponseEntity<>(body, HttpStatus.INTERNAL_SERVER_ERROR);
  }

  private Map<String, Object> createErrorBody(
      HttpStatus status, String error, String message, WebRequest request) {

    Map<String, Object> body = new LinkedHashMap<>();
    body.put("timestamp", Instant.now());
    body.put("status", status.value());
    body.put("error", error);
    body.put("message", message);
    body.put("path", extractPath(request));

    return body;
  }

  private String extractPath(WebRequest request) {
    String description = request.getDescription(false);
    return description.replace("uri=", "");
  }
}
