package com.example.gateway.domain.entity;

/**
 * Supported Identity Providers.
 * Stored in the user's session to allow for correct token validation routing.
 */
public enum IdpProvider {
  //For external users authenticating via Ping Identity.
  PING_IDENTITY,
   //For internal users authenticating via Microsoft Entra ID.
  MICROSOFT_ENTRA
}
