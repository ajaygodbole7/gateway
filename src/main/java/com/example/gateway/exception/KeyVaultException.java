package com.example.gateway.exception;


/**
 * Key Vault Exception
 */
public class KeyVaultException extends RuntimeException {
  public KeyVaultException(String message) {
    super(message);
  }

  public KeyVaultException(String message, Throwable cause) {
    super(message, cause);
  }
}
