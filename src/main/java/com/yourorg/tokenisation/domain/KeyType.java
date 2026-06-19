package com.yourorg.tokenisation.domain;

/**
 * Discriminator for {@code key_versions} rows.
 *
 * <p>{@code KEK} rows hold KMS-wrapped key encryption keys used for envelope encryption.
 * {@code HMAC} rows hold HMAC secrets used for PAN hashing and de-duplication.
 */
public enum KeyType {
    KEK,
    HMAC
}
