package com.example.gateway.adapter.keyvault.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Azure Key Vault Secret Response
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SecretResponse(
    String value,
    String id,
    SecretAttributes attributes
) {
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record SecretAttributes(
      boolean enabled,
      long created,
      long updated
  ) {}
}
