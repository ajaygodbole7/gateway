package com.example.gateway.service;

import com.example.gateway.domain.entity.IdpProvider;
import com.example.gateway.domain.entity.UserPrincipal;
import com.example.gateway.exception.SessionException;
import com.example.gateway.properties.ApplicationProperties;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.servlet.http.HttpServletRequest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

/**
 * High-performance session management service.
 * Uses Redis hash structures as the single source of truth for session data.
 */
@Service
@Slf4j
public class SessionService {

    public static final String SESSION_KEY_PREFIX = "session:";
    public static final String FIELD_PROVIDER = "provider";
    public static final String FIELD_USER_ID = "userId";
    public static final String FIELD_USERNAME = "username";
    public static final String FIELD_EMAIL = "email";
    public static final String FIELD_FIRST_NAME = "firstName";
    public static final String FIELD_LAST_NAME = "lastName";
    public static final String FIELD_LOGIN_TIME = "loginTime";
    public static final String FIELD_CREATED_AT = "createdAt";
    public static final String FIELD_LAST_REFRESH = "lastRefresh";
    public static final String FIELD_FINGERPRINT = "fingerprint";
    public static final String FIELD_IP = "ip";
    public static final String FIELD_ID_TOKEN = "idToken";
    private static final String USER_SESSIONS_INDEX_PREFIX = "user_sessions:";
    private static final int SESSION_ID_ENTROPY_BYTES = 32;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final RedisTemplate<String, String> redisTemplate;
    private final EncryptionService encryptionService;
    private final SessionBindingService sessionBindingService;
    private final ApplicationProperties properties;
    private final Cache<String, Authentication> sessionCache;

    public SessionService(
            RedisTemplate<String, String> redisTemplate,
            EncryptionService encryptionService,
            SessionBindingService sessionBindingService,
            ApplicationProperties properties) {
        this.redisTemplate = redisTemplate;
        this.encryptionService = encryptionService;
        this.sessionBindingService = sessionBindingService;
        this.properties = properties;

        ApplicationProperties.CacheProperties.SessionCacheProperties cacheProps =
                properties.cache().session();

        this.sessionCache = Caffeine.newBuilder()
                .maximumSize(cacheProps.maxSize())
                .expireAfterWrite(cacheProps.localTtl())
                .recordStats()
                .build();
    }

    public Optional<Authentication> authenticateBySessionId(String sessionId, HttpServletRequest request) {
        if (!isValidSessionId(sessionId)) {
            return Optional.empty();
        }

        Authentication cachedAuth = sessionCache.getIfPresent(sessionId);
        if (cachedAuth != null) {
            return Optional.of(cachedAuth);
        }

        try {
            String sessionKey = SESSION_KEY_PREFIX + sessionId;

            List<Object> results = redisTemplate.executePipelined(new SessionCallback<Object>() {
                @Override
                public Object execute(@NonNull RedisOperations operations) {
                    @SuppressWarnings("unchecked")
                    RedisOperations<String, String> redisOps = (RedisOperations<String, String>) operations;
                    redisOps.opsForHash().entries(sessionKey);
                    redisOps.getExpire(sessionKey, TimeUnit.SECONDS);
                    return null;
                }
            });

            @SuppressWarnings("unchecked")
            Map<String, String> sessionData = (Map<String, String>) results.get(0);
            Long ttlSeconds = (Long) results.get(1);

            if (sessionData == null || sessionData.isEmpty() || ttlSeconds == null || ttlSeconds <= 0) {
                return Optional.empty();
            }

            long createdAt = Long.parseLong(sessionData.get(FIELD_CREATED_AT));
            long absoluteTimeoutMillis =
                    TimeUnit.HOURS.toMillis(properties.security().session().absoluteTimeoutHours());
            if (System.currentTimeMillis() - createdAt > absoluteTimeoutMillis) {
                invalidateSession(sessionId);
                return Optional.empty();
            }

            String currentFingerprint = sessionBindingService.generateClientFingerprint(request);
            if (!currentFingerprint.equals(sessionData.get(FIELD_FINGERPRINT))) {
                invalidateSession(sessionId);
                return Optional.empty();
            }

            long slidingWindowSeconds = properties.security().session().slidingWindowMinutes() * 60L;
            double refreshThreshold = properties.cache().session().refreshThreshold();
            if (ttlSeconds < slidingWindowSeconds * refreshThreshold) {
                redisTemplate.expire(sessionKey, slidingWindowSeconds, TimeUnit.MINUTES);
            }

            UserPrincipal userPrincipal = new UserPrincipal(
                    sessionData.get(FIELD_USER_ID),
                    sessionData.get(FIELD_USERNAME),
                    sessionData.get(FIELD_EMAIL),
                    sessionData.get(FIELD_FIRST_NAME),
                    sessionData.get(FIELD_LAST_NAME),
                    Long.parseLong(sessionData.get(FIELD_LOGIN_TIME)),
                    ttlSeconds);
            Authentication auth = new UsernamePasswordAuthenticationToken(userPrincipal, null, Collections.emptyList());

            sessionCache.put(sessionId, auth);
            return Optional.of(auth);

        } catch (Exception e) {
            log.error("Session authentication failed for session: {}", maskSessionId(sessionId), e);
            sessionCache.invalidate(sessionId);
            return Optional.empty();
        }
    }

    public String createAuthenticatedSession(
            IdpProvider idpProvider, UserPrincipal userPrincipal, String idToken, HttpServletRequest request) {
        String sessionId = generateSecureSessionId();
        String sessionKey = SESSION_KEY_PREFIX + sessionId;
        String userId = userPrincipal.userId();

        try {
            String encryptedIdToken = encryptionService.encrypt(idToken);
            Map<String, String> sessionData = new HashMap<>();
            sessionData.put(FIELD_PROVIDER, idpProvider.name());
            sessionData.put(FIELD_USER_ID, userId);
            sessionData.put(FIELD_USERNAME, userPrincipal.username());
            sessionData.put(FIELD_EMAIL, userPrincipal.email());
            sessionData.put(FIELD_FIRST_NAME, userPrincipal.firstName());
            sessionData.put(FIELD_LAST_NAME, userPrincipal.lastName());
            sessionData.put(FIELD_LOGIN_TIME, String.valueOf(userPrincipal.loginTime()));
            sessionData.put(FIELD_CREATED_AT, String.valueOf(System.currentTimeMillis()));
            sessionData.put(FIELD_LAST_REFRESH, String.valueOf(System.currentTimeMillis()));
            sessionData.put(FIELD_FINGERPRINT, sessionBindingService.generateClientFingerprint(request));
            sessionData.put(FIELD_IP, sessionBindingService.getClientIpAddress(request));
            sessionData.put(FIELD_ID_TOKEN, encryptedIdToken);

            int slidingWindowMinutes = properties.security().session().slidingWindowMinutes();

            redisTemplate.executePipelined(new SessionCallback<Object>() {
                @Override
                public Object execute(@NonNull RedisOperations operations) {
                    @SuppressWarnings("unchecked")
                    RedisOperations<String, String> redisOps = (RedisOperations<String, String>) operations;
                    redisOps.opsForHash().putAll(sessionKey, sessionData);
                    redisOps.expire(sessionKey, slidingWindowMinutes, TimeUnit.MINUTES);
                    String userKey = USER_SESSIONS_INDEX_PREFIX + userId;
                    redisOps.opsForSet().add(userKey, sessionId);
                    redisOps.expire(userKey, properties.security().session().absoluteTimeoutHours(), TimeUnit.HOURS);
                    return null;
                }
            });
            return sessionId;
        } catch (Exception e) {
            throw new SessionException("Failed to create session", e);
        }
    }

    public void updateSessionIdToken(String sessionId, String newIdToken) {
        if (!isValidSessionId(sessionId)) return;
        try {
            String sessionKey = SESSION_KEY_PREFIX + sessionId;
            String encryptedToken = encryptionService.encrypt(newIdToken);
            HashOperations<String, String, String> hashOps = redisTemplate.opsForHash();
            hashOps.put(sessionKey, FIELD_ID_TOKEN, encryptedToken);
            hashOps.put(sessionKey, FIELD_LAST_REFRESH, String.valueOf(System.currentTimeMillis()));
            sessionCache.invalidate(sessionId);
        } catch (Exception e) {
            log.error("Failed to update session ID token", e);
        }
    }

    public void invalidateSession(String sessionId) {
        if (!isValidSessionId(sessionId)) return;
        String sessionKey = SESSION_KEY_PREFIX + sessionId;
        try {
            String userId = redisTemplate.<String, String>opsForHash().get(sessionKey, FIELD_USER_ID);
            if (userId != null) {
                redisTemplate.opsForSet().remove(USER_SESSIONS_INDEX_PREFIX + userId, sessionId);
            }
        } catch (Exception e) {
            log.error("Could not clean up user-session index for session: {}.", sessionId, e);
        } finally {
            redisTemplate.delete(sessionKey);
            sessionCache.invalidate(sessionId);
        }
    }

    private String generateSecureSessionId() {
        byte[] randomBytes = new byte[SESSION_ID_ENTROPY_BYTES];
        SECURE_RANDOM.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private boolean isValidSessionId(String sessionId) {
        return sessionId != null && sessionId.length() >= 42 && sessionId.length() <= 44;
    }

    private String maskSessionId(String sessionId) {
        if (sessionId == null || sessionId.length() < 8) return "INVALID";
        return sessionId.substring(0, 8) + "...";
    }
}
