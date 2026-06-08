package com.yourorg.tokenisation.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Configuration properties for the tokenisation service.
 *
 * <p>Bound from the {@code tokenisation} namespace in {@code application.yml}:
 * <pre>{@code
 * tokenisation:
 *   allowed-card-schemes:
 *     - MC
 * }</pre>
 */
@Component
@ConfigurationProperties(prefix = "tokenisation")
public class TokenisationProperties {

    /**
     * List of card scheme codes accepted by the tokenise endpoint.
     * Values are case-sensitive. Defaults to {@code [MC]}.
     * Add entries here to enable additional schemes (e.g. {@code VISA}) without code changes.
     */
    private List<String> allowedCardSchemes = List.of("MC");

    /**
     * Returns the list of permitted card scheme codes.
     *
     * @return immutable list of allowed scheme strings
     */
    public List<String> getAllowedCardSchemes() {
        return allowedCardSchemes;
    }

    /**
     * Sets the list of permitted card scheme codes.
     *
     * @param allowedCardSchemes the schemes to allow; must not be null or empty
     */
    public void setAllowedCardSchemes(List<String> allowedCardSchemes) {
        this.allowedCardSchemes = allowedCardSchemes;
    }
}
