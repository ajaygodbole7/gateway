package com.example.gateway.domain.entity;

/**
 * User Principal - Minimal authenticated user identity
 */
public record UserPrincipal(
    String userId,
    String username,
    String email,
    String firstName,
    String lastName,
    Long loginTime,
    Long sessionTimeout
) {}
