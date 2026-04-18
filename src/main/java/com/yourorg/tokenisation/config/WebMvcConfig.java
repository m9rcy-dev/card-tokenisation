package com.yourorg.tokenisation.config;

import com.yourorg.tokenisation.monitoring.MetricsCollector;
import com.yourorg.tokenisation.monitoring.MetricsInterceptor;
import com.yourorg.tokenisation.security.RateLimitInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Spring MVC configuration.
 *
 * <p>Registers two interceptors:
 * <ul>
 *   <li>{@link RateLimitInterceptor} — scoped to {@code GET /api/v1/tokens/**} to enforce
 *       per-merchant and per-service rate limits on detokenisation only.
 *   <li>{@link MetricsInterceptor} — applied to all API paths to count successful
 *       tokenise/detokenise requests and server errors.
 * </ul>
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    private final DetokenisationProperties detokenisationProperties;
    private final MetricsCollector metricsCollector;

    /**
     * Constructs the MVC configuration with required collaborators.
     *
     * @param detokenisationProperties rate-limit thresholds; must not be null
     * @param metricsCollector         shared metrics counter store; must not be null
     */
    public WebMvcConfig(DetokenisationProperties detokenisationProperties,
                        MetricsCollector metricsCollector) {
        this.detokenisationProperties = detokenisationProperties;
        this.metricsCollector = metricsCollector;
    }

    /**
     * Registers the rate-limit and metrics interceptors.
     *
     * <p>The {@link RateLimitInterceptor} only intercepts {@code GET /api/v1/tokens/**}.
     * The {@link MetricsInterceptor} intercepts all {@code /api/**} paths.
     *
     * @param registry the interceptor registry provided by Spring MVC
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new RateLimitInterceptor(detokenisationProperties))
                .addPathPatterns("/api/v1/tokens/**");

        registry.addInterceptor(new MetricsInterceptor(metricsCollector))
                .addPathPatterns("/api/**");
    }
}
