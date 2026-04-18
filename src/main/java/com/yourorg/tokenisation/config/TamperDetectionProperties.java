package com.yourorg.tokenisation.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for key-version row tamper detection.
 *
 * <p>Bound from the {@code tokenisation.tamper-detection} namespace in {@code application.yml}:
 * <pre>{@code
 * tokenisation:
 *   tamper-detection:
 *     signing-secret: ${TAMPER_DETECTION_SECRET}
 * }</pre>
 *
 * <p>The signing secret is used by {@link com.yourorg.tokenisation.crypto.TamperDetector}
 * to compute and verify HMAC-SHA256 checksums on {@code key_versions} rows. It must be
 * distinct from both the KEK and the PAN hash secret to limit blast radius if any single
 * secret is exposed. The value should be at least 32 bytes of high-entropy random data,
 * sourced from a secrets manager (e.g. AWS Secrets Manager or HashiCorp Vault) in production.
 */
@Component
@ConfigurationProperties(prefix = "tokenisation.tamper-detection")
public class TamperDetectionProperties {

    /**
     * HMAC-SHA256 signing secret for {@code key_versions} row integrity checks.
     * Must be at least 32 bytes. Never log or expose this value.
     */
    private String signingSecret;

    /**
     * Returns the HMAC-SHA256 signing secret.
     *
     * @return the signing secret; never null after binding
     */
    public String getSigningSecret() {
        return signingSecret;
    }

    /**
     * Sets the HMAC-SHA256 signing secret.
     *
     * @param signingSecret the signing secret; must not be null or blank
     */
    public void setSigningSecret(String signingSecret) {
        this.signingSecret = signingSecret;
    }
}
