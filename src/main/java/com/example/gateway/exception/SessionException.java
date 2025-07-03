package com.example.gateway.exception;

/**
 * Encryption Exception
 */
public class SessionException extends RuntimeException {
  public SessionException(String message) {
    super(message);
  }

  public SessionException(String message, Throwable cause) {
    super(message, cause);
  }
}
