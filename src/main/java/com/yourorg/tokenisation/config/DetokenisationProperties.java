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
 *     per-merchant-per-minute: 1000
 *     per-service-per-minute: 10000
 * }</pre>
 *
 * <p>The two limits are applied independently. A request that exceeds either limit
 * is rejected with HTTP 429. The per-merchant limit protects against individual
 * merchant over-use; the per-service limit caps aggregate throughput.
 */
@Component
@ConfigurationProperties(prefix = "detokenisation.rate-limit")
public class DetokenisationProperties {

    /**
     * Maximum number of detokenisation requests a single merchant may make per minute.
     * Defaults to 1000. Tests override this to a high value to avoid spurious 429s.
     */
    private int perMerchantPerMinute = 1000;

    /**
     * Maximum total detokenisation requests across all merchants per minute.
     * Defaults to 10000.
     */
    private int perServicePerMinute = 10000;

    /**
     * Returns the per-merchant per-minute request limit.
     *
     * @return the per-merchant limit
     */
    public int getPerMerchantPerMinute() {
        return perMerchantPerMinute;
    }

    /**
     * Sets the per-merchant per-minute request limit.
     *
     * @param perMerchantPerMinute the new limit; must be positive
     */
    public void setPerMerchantPerMinute(int perMerchantPerMinute) {
        this.perMerchantPerMinute = perMerchantPerMinute;
    }

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
