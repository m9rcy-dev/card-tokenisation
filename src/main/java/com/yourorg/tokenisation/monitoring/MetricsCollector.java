package com.yourorg.tokenisation.monitoring;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe in-memory counter store for API metrics.
 *
 * <p>Counters are incremented by {@link MetricsInterceptor} after each HTTP request completes.
 * Values are reset to zero when the application restarts — this is intentional for a
 * single-node in-process metrics store.
 *
 * <p>All counter reads and writes use {@link AtomicLong} for lock-free thread safety.
 * The {@code startTime} is set once at bean creation and never mutated.
 */
@Component
public class MetricsCollector {

    private final Instant startTime = Instant.now();

    private final AtomicLong tokeniseRequests = new AtomicLong();
    private final AtomicLong detokeniseRequests = new AtomicLong();
    private final AtomicLong serverErrorCount = new AtomicLong();

    /** Increments the successful tokenisation counter. */
    public void recordTokenise() {
        tokeniseRequests.incrementAndGet();
    }

    /** Increments the successful detokenisation counter. */
    public void recordDetokenise() {
        detokeniseRequests.incrementAndGet();
    }

    /** Increments the server error counter (HTTP 5xx responses). */
    public void recordServerError() {
        serverErrorCount.incrementAndGet();
    }

    /**
     * Returns the total number of successful tokenisations since startup.
     *
     * @return non-negative count
     */
    public long getTokeniseRequests() {
        return tokeniseRequests.get();
    }

    /**
     * Returns the total number of successful detokenisations since startup.
     *
     * @return non-negative count
     */
    public long getDetokeniseRequests() {
        return detokeniseRequests.get();
    }

    /**
     * Returns the total number of HTTP 5xx server error responses since startup.
     *
     * @return non-negative count
     */
    public long getServerErrorCount() {
        return serverErrorCount.get();
    }

    /**
     * Returns the number of seconds elapsed since the application started.
     *
     * @return uptime in whole seconds; always ≥ 0
     */
    public long getUptimeSeconds() {
        return Duration.between(startTime, Instant.now()).toSeconds();
    }

    /**
     * Returns the wall-clock timestamp when this bean was initialised (i.e. when the app started).
     *
     * @return the startup instant
     */
    public Instant getStartTime() {
        return startTime;
    }
}
