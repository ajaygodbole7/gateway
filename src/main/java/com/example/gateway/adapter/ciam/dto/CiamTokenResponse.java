package com.example.gateway.adapter.ciam.dto;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * OAuth2 Token Response DTO
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CiamTokenResponse(
    @JsonProperty("access_token")
    String accessToken,
    @JsonProperty("token_type")
    String tokenType,
    @JsonProperty("expires_in")
    Long expiresIn,
    @JsonProperty("refresh_token")
    String refreshToken,
    @JsonProperty("id_token")
    String idToken,
    @JsonProperty("scope")
    String scope,
    @JsonProperty("error")
    String error,
    @JsonProperty("error_description")
    String errorDescription,
    @JsonProperty("error_uri")
    String errorUri
) {

  public boolean isError() {
    return error != null;
  }

  public boolean hasIdToken() {
    return idToken != null && !idToken.isEmpty();
  }
}
