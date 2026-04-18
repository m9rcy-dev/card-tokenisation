package com.yourorg.tokenisation.rotation;

import org.springframework.context.ApplicationEvent;

import java.util.UUID;

/**
 * Application event published when a key compromise is detected and emergency rotation is initiated.
 *
 * <p>Published by {@link KeyRotationService#initiateEmergencyRotation} synchronously before
 * returning. Listeners are invoked in the same thread (synchronous Spring application events)
 * unless configured otherwise.
 *
 * <p>Security alert delivery (webhook, email, PagerDuty) is handled by
 * {@link SecurityAlertListener} — the service is decoupled from delivery mechanisms
 * via this event.
 */
public class SecurityAlertEvent extends ApplicationEvent {

    private final UUID compromisedKeyVersionId;
    private final String message;

    /**
     * Constructs a security alert event.
     *
     * @param source                  the publishing object (the {@code KeyRotationService})
     * @param compromisedKeyVersionId the ID of the compromised key version
     * @param message                 human-readable description of the alert
     */
    public SecurityAlertEvent(Object source, UUID compromisedKeyVersionId, String message) {
        super(source);
        this.compromisedKeyVersionId = compromisedKeyVersionId;
        this.message = message;
    }

    /**
     * Returns the ID of the key version that was marked compromised.
     *
     * @return the compromised key version UUID
     */
    public UUID getCompromisedKeyVersionId() {
        return compromisedKeyVersionId;
    }

    /**
     * Returns the human-readable alert message.
     *
     * @return the alert message
     */
    public String getMessage() {
        return message;
    }
}
