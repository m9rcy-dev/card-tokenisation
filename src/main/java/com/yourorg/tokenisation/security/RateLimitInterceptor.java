package com.yourorg.tokenisation.security;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.yourorg.tokenisation.config.DetokenisationProperties;
import com.yourorg.tokenisation.exception.RateLimitExceededException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Spring MVC {@link HandlerInterceptor} that enforces a per-service rate limit on the
 * detokenisation endpoint ({@code GET /api/v1/tokens/{token}}).
 *
 * <p>A single global counter tracks total requests per minute. When the counter exceeds
 * the configured threshold, the request is rejected with {@link RateLimitExceededException},
 * which {@code GlobalExceptionHandler} maps to HTTP 429.
 *
 * <p>The fixed-window approach is simple and sufficient for single-node deployments.
 * A sliding-window or token-bucket implementation backed by Redis would be required
 * for accurate limiting across multiple nodes.
 */
@Slf4j
public class RateLimitInterceptor implements HandlerInterceptor {

    private static final String SERVICE_COUNTER_KEY = "__service__";

    /**
     * Fixed-window counter keyed by {@link #SERVICE_COUNTER_KEY}.
     * Entry expires 1 minute after creation (the first request in a window).
     */
    private final LoadingCache<String, AtomicLong> counters;

    private final DetokenisationProperties properties;

    /**
     * Constructs the interceptor with the given rate-limit configuration.
     *
     * @param properties the rate-limit thresholds; must not be null
     */
    public RateLimitInterceptor(DetokenisationProperties properties) {
        this.properties = properties;
        this.counters = Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterWrite(1, TimeUnit.MINUTES)
                .build(key -> new AtomicLong(0));
    }

    /**
     * Checks the per-service rate limit before allowing the request through.
     *
     * <p>Increments the service counter atomically. If it exceeds the configured
     * threshold, throws {@link RateLimitExceededException}. The increment is not
     * rolled back on rejection — this prevents trivially gaming the limit.
     *
     * @param request  the incoming HTTP request
     * @param response the HTTP response (not modified — exception handling writes the response)
     * @param handler  the handler to invoke (not used)
     * @return {@code true} if the request is within limits and should proceed
     * @throws RateLimitExceededException if the service rate limit is exceeded
     */
    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws Exception {
        if (!"GET".equalsIgnoreCase(request.getMethod())) {
            return true;
        }

        long serviceCount = incrementAndGet(SERVICE_COUNTER_KEY);
        int serviceLimit = properties.getPerServicePerMinute();

        if (serviceCount > serviceLimit) {
            log.warn("Service-wide rate limit exceeded: {} requests in current window (limit {})",
                    serviceCount, serviceLimit);
            throw new RateLimitExceededException(
                    "Service rate limit exceeded: limit is " + serviceLimit + " requests per minute");
        }

        return true;
    }

    // ── Private ──────────────────────────────────────────────────────────────

    /**
     * Atomically increments the counter for the given key, creating the entry if absent.
     *
     * @param key the cache key
     * @return the counter value after incrementing
     */
    private long incrementAndGet(String key) {
        AtomicLong counter = counters.get(key);
        return counter.incrementAndGet();
    }
}
