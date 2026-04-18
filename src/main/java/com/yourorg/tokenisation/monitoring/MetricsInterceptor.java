package com.yourorg.tokenisation.monitoring;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Spring MVC {@link HandlerInterceptor} that records API request metrics after each
 * HTTP response is committed.
 *
 * <p>Increments counters in {@link MetricsCollector}:
 * <ul>
 *   <li>Tokenise counter: {@code POST /api/v1/tokens} → HTTP 2xx
 *   <li>Detokenise counter: {@code GET /api/v1/tokens/{token}} → HTTP 200
 *   <li>Server error counter: any HTTP 5xx response on any endpoint
 * </ul>
 *
 * <p>Client errors (4xx) are intentionally excluded from the error counter — they represent
 * expected application behaviour (validation failures, not-found, rate limits, etc.)
 * and are handled via audit log events.
 *
 * <p>Registered by {@link com.yourorg.tokenisation.config.WebMvcConfig} for all paths
 * so that the server-error counter captures the full picture.
 */
public class MetricsInterceptor implements HandlerInterceptor {

    private static final String TOKENISE_URI = "/api/v1/tokens";
    private static final String DETOKENISE_PREFIX = "/api/v1/tokens/";

    private final MetricsCollector metricsCollector;

    /**
     * Constructs the interceptor with the shared metrics store.
     *
     * @param metricsCollector the counter store; must not be null
     */
    public MetricsInterceptor(MetricsCollector metricsCollector) {
        this.metricsCollector = metricsCollector;
    }

    /**
     * Records metrics after the handler completes and the response status is known.
     *
     * @param request  the HTTP request
     * @param response the HTTP response (status is set at this point)
     * @param handler  the executed handler (unused)
     * @param ex       any exception thrown by the handler; {@code null} on success
     */
    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, Exception ex) {
        String method = request.getMethod();
        String uri = request.getRequestURI();
        int status = response.getStatus();

        if ("POST".equals(method) && TOKENISE_URI.equals(uri) && status >= 200 && status < 300) {
            metricsCollector.recordTokenise();
        } else if ("GET".equals(method) && uri.startsWith(DETOKENISE_PREFIX) && status == 200) {
            metricsCollector.recordDetokenise();
        }

        if (status >= 500) {
            metricsCollector.recordServerError();
        }
    }
}
