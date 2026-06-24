package com.yourorg.tokenisation.domain;

/**
 * Discriminator for {@code key_versions} rows.
 *
 * <p>{@code DEK} rows hold KMS-protected data encryption keys used for direct PAN encryption.
 * {@code HMAC} rows hold HMAC secrets used for PAN hashing and de-duplication.
 */
public enum KeyType {
    DEK,
    HMAC
}
