package com.yourorg.tokenisation.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security configuration for the card tokenisation API.
 *
 * <p>All API endpoints require authentication. The tokenisation and detokenisation
 * endpoints enforce JWT-based service authentication; merchant ID is extracted from
 * JWT claims and never from the request body to prevent spoofing.
 *
 * <p>mTLS configuration is applied at the infrastructure level (load balancer / ingress)
 * rather than here — this configuration covers application-layer JWT verification.
 *
 * <p>The current configuration disables CSRF (not applicable for stateless service-to-service APIs)
 * and permits all requests temporarily until JWT configuration is wired in Phase 2.
 * This placeholder will be replaced with full JWT extraction and merchant scope enforcement.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Configures the HTTP security filter chain.
     *
     * <p>CSRF is disabled — this API is consumed by backend services using JWT bearer tokens,
     * not by browsers, so CSRF protection does not apply.
     *
     * @param http the {@link HttpSecurity} builder provided by Spring Security
     * @return the configured {@link SecurityFilterChain}
     * @throws Exception if the security configuration cannot be applied
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                // Permit all requests temporarily — JWT enforcement added in Phase 2
                // (P2 adds merchant ID extraction from JWT claims)
                .anyRequest().permitAll()
            );
        return http.build();
    }
}
