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
 * Spring MVC {@link HandlerInterceptor} that enforces per-merchant and per-service
 * rate limits on the detokenisation endpoint ({@code GET /api/v1/tokens/{token}}).
 *
 * <p>Limits are applied using a fixed-window counter backed by Caffeine:
 * <ul>
 *   <li>A per-merchant counter tracks requests from each {@code X-Merchant-ID} value.
 *   <li>A global counter tracks total requests across all merchants.
 * </ul>
 * Each counter window is 1 minute, starting from the first request in that window.
 * When either counter exceeds its configured threshold, the request is rejected with
 * {@link RateLimitExceededException}, which {@code GlobalExceptionHandler} maps to HTTP 429.
 *
 * <p>If the {@code X-Merchant-ID} header is absent, the request is rejected with a
 * {@link RateLimitExceededException} to avoid bypassing per-merchant limits. (Full
 * header validation will move to JWT claims in a future phase.)
 *
 * <p>The fixed-window approach is simple and sufficient for single-node deployments.
 * A sliding-window or token-bucket implementation backed by Redis would be required
 * for accurate limiting across multiple nodes.
 */
@Slf4j
public class RateLimitInterceptor implements HandlerInterceptor {

    private static final String SERVICE_COUNTER_KEY = "__service__";

    /**
     * Fixed-window counters keyed by merchant ID or {@link #SERVICE_COUNTER_KEY}.
     * Entries expire 1 minute after creation (the first request in a window).
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
     * Checks per-merchant and per-service rate limits before allowing the request through.
     *
     * <p>Increments both counters atomically. If either exceeds its configured threshold,
     * throws {@link RateLimitExceededException}. The increment is not rolled back on
     * rejection — this prevents trivially gaming the limit by sending requests that
     * just barely cross the threshold.
     *
     * @param request  the incoming HTTP request
     * @param response the HTTP response (not modified — exception handling writes the response)
     * @param handler  the handler to invoke (not used)
     * @return {@code true} if the request is within limits and should proceed
     * @throws RateLimitExceededException if either rate limit is exceeded
     */
    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws Exception {
        // Rate limiting applies only to the detokenisation GET endpoint.
        // Tokenisation (POST) is unrestricted at the interceptor layer.
        if (!"GET".equalsIgnoreCase(request.getMethod())) {
            return true;
        }

        String merchantId = request.getHeader("X-Merchant-ID");
        if (merchantId == null || merchantId.isBlank() || merchantId.length() > 256) {
            throw new RateLimitExceededException("X-Merchant-ID header is required for detokenisation and must be ≤256 characters");
        }

        long merchantCount = incrementAndGet(merchantId);
        long serviceCount = incrementAndGet(SERVICE_COUNTER_KEY);

        int merchantLimit = properties.getPerMerchantPerMinute();
        int serviceLimit = properties.getPerServicePerMinute();

        if (merchantCount > merchantLimit) {
            log.warn("Rate limit exceeded for merchant [{}]: {} requests in current window (limit {})",
                    merchantId, merchantCount, merchantLimit);
            throw new RateLimitExceededException(
                    "Rate limit exceeded for merchant " + merchantId
                            + ": limit is " + merchantLimit + " requests per minute");
        }

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
     * @param key the cache key (merchant ID or service sentinel)
     * @return the counter value after incrementing
     */
    private long incrementAndGet(String key) {
        AtomicLong counter = counters.get(key);
        // counter is never null — the CacheLoader always returns a new AtomicLong(0)
        return counter.incrementAndGet();
    }
}
