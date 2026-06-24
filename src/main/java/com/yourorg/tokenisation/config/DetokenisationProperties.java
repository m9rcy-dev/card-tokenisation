package com.yourorg.tokenisation.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for the detokenisation rate limiter.
 *
 * <p>Bound from the {@code detokenisation.rate-limit} namespace in {@code application.yml}:
 * <pre>{@code
 * detokenisation:
 *   rate-limit:
 *     per-service-per-minute: 10000
 * }</pre>
 *
 * <p>The service limit caps aggregate detokenisation throughput across all callers.
 */
@Component
@ConfigurationProperties(prefix = "detokenisation.rate-limit")
public class DetokenisationProperties {

    /**
     * Maximum total detokenisation requests per minute across all callers.
     * Defaults to 10000.
     */
    private int perServicePerMinute = 10000;

    /**
     * Returns the per-service per-minute request limit.
     *
     * @return the per-service limit
     */
    public int getPerServicePerMinute() {
        return perServicePerMinute;
    }

    /**
     * Sets the per-service per-minute request limit.
     *
     * @param perServicePerMinute the new limit; must be positive
     */
    public void setPerServicePerMinute(int perServicePerMinute) {
        this.perServicePerMinute = perServicePerMinute;
    }
}
