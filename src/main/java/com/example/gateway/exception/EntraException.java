package com.example.gateway.exception;

public class EntraException extends RuntimeException {
  public EntraException(String message) {
    super(message);
  }

  public EntraException(String message, Throwable cause) {
    super(message, cause);
  }
}
