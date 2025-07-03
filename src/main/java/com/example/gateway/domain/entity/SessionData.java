package com.example.gateway.domain.entity;

/**
 * Session Data stored in Redis
 */
public record SessionData(
        UserPrincipal userPrincipal,
        String idToken,
        long createdAt,
        long lastAccessed,
        String clientFingerprint,
        String lastIpAddress) {}
