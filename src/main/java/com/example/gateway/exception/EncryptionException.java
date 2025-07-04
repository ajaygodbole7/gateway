package com.example.gateway.exception;

/**
 * Encryption Exception
 */
public class EncryptionException extends RuntimeException {
  public EncryptionException(String message) {
    super(message);
  }

  public EncryptionException(String message, Throwable cause) {
    super(message, cause);
  }
}
