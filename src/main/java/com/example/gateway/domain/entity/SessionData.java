package com.example.gateway.domain.entity;

/**
 * Represents the data associated with a user's session.
 * Mirrors the data stored in a Redis Hash.
 */
public record SessionData(
    /**
     * The Identity Provider that authenticated this user session.
     */
    IdpProvider idpProvider,

    /**
     * The core, non-sensitive details of the authenticated user.
     */
    UserPrincipal userPrincipal,

    /**
     * The user's Identity Token, encrypted before being stored.
     * Note: This field holds the Base64 representation of the *encrypted* JWT.
     */
    String idToken,

    /**
     * The timestamp (in milliseconds) when the session was created.
     */
    long createdAt,

    /**
     * The timestamp (in milliseconds) when the session was last accessed.
     */
    long lastAccessed,

    /**
     * A hash of the user's browser/client attributes to help detect session hijacking.
     */
    String clientFingerprint,

    /**
     * The last known IP address of the user who accessed this session.
     */
    String lastIpAddress
) {}
