package com.yourorg.tokenisation.domain;

/**
 * Records why a key rotation was initiated.
 *
 * <p>The reason determines operational urgency: {@code COMPROMISE} triggers
 * immediate suspension of detokenisation for affected tokens and elevated-priority
 * re-encryption batches, whereas {@code SCHEDULED} rotations run at normal pace.
 */
public enum RotationReason {

    /**
     * Annual compliance rotation triggered before the key's {@code rotate_by} deadline.
     * Normal batch re-encryption pace applies.
     */
    SCHEDULED,

    /**
     * Key material has been (or is suspected to have been) exposed.
     * Detokenisation is suspended immediately; re-encryption runs at elevated priority.
     */
    COMPROMISE,

    /**
     * Operator-initiated rotation outside the scheduled cycle — e.g. post-incident
     * review, infrastructure migration, or pre-emptive action.
     */
    MANUAL
}
