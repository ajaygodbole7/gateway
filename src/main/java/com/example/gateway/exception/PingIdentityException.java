package com.example.gateway.exception;

public class PingIdentityException extends RuntimeException {
  public PingIdentityException(String message) {
    super(message);
  }

  public PingIdentityException(String message, Throwable cause) {
    super(message, cause);
  }
}
