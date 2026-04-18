package com.yourorg.tokenisation.rotation;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Handles {@link SecurityAlertEvent} by notifying the security team of a key compromise.
 *
 * <p>The current implementation logs the alert at {@code ERROR} level and is designed
 * as an extension point — production deployments should configure an outbound webhook
 * or email integration by overriding or supplementing this listener.
 *
 * <p>Delivery mechanisms that can be added without changing {@link KeyRotationService}:
 * <ul>
 *   <li>Webhook — HTTP POST to a configurable URL (PagerDuty, Opsgenie, Slack)
 *   <li>Email — via Spring Mail ({@code JavaMailSender})
 *   <li>SNS — AWS Simple Notification Service for multi-channel fan-out
 * </ul>
 *
 * <p>This listener runs synchronously in the same thread as the event publisher.
 * Alert delivery failures (e.g. webhook timeout) are caught and logged — they must
 * not interrupt the emergency rotation flow.
 */
@Component
@Slf4j
public class SecurityAlertListener {

    /**
     * Handles a security alert event triggered by an emergency key rotation.
     *
     * <p>Logs the alert at {@code ERROR} level so that it is captured by log aggregation
     * (CloudWatch, Datadog, Splunk) and triggers any configured log-based alerting rules.
     * This is the baseline delivery mechanism — production deployments should add
     * webhook/email delivery here.
     *
     * @param event the security alert event; never null
     */
    @EventListener
    public void handleSecurityAlert(SecurityAlertEvent event) {
        try {
            log.error("SECURITY ALERT — Key compromise detected: keyVersionId=[{}] message=[{}]",
                    event.getCompromisedKeyVersionId(),
                    event.getMessage());
            // TODO (production): deliver to configured webhook / email / SNS
        } catch (Exception deliveryException) {
            // Alert delivery must not interrupt the rotation flow
            log.error("Failed to deliver security alert for keyVersionId=[{}]: {}",
                    event.getCompromisedKeyVersionId(),
                    deliveryException.getMessage(),
                    deliveryException);
        }
    }
}
