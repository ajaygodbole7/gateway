package com.example.gateway.web.rest;

public final class ApiConstants {

  public static final class ApiPath {
    // Base paths
    public static final String AUTH_BASE = "/auth";
    public static final String INTERNAL_BASE = "/internal";
    public static final String API_BASE = "/api";
    public static final String HEALTH_BASE = "/health";

    // Auth paths
    public static final String LOGIN = "/login";
    public static final String CALLBACK = "/callback";
    public static final String LOGOUT = "/logout";
    public static final String REFRESH = "/refresh";
    public static final String STATUS = "/status";

    // Session paths
    public static final String SESSION = "/session";
    public static final String ME = "/me";
    public static final String INFO = "/info";

    // Internal paths
    public static final String AUTH_CHECK = "/auth-check";
    public static final String CURRENT_USER = "/current-user";

    // Health paths
    public static final String LIVE = "/live";
    public static final String READY = "/ready";

    private ApiPath() {}
  }

  private ApiConstants() {}
}
