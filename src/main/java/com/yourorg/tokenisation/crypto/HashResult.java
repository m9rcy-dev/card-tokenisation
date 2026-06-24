package com.yourorg.tokenisation.crypto;

/**
 * Carries the result of a PAN hash operation, pairing the hash value with the
 * HMAC key version that produced it.
 *
 * <p>The version ID is stored alongside the hash in {@code token_vault.hmac_key_version_id}
 * so that the HMAC rotation batch can identify which records need re-hashing.
 *
 * @param hash          64-character lowercase hex HMAC-SHA256 of the PAN
 * @param hmacVersionId UUID string of the {@link com.yourorg.tokenisation.domain.KeyVersion}
 *                      (type HMAC) whose secret was used to produce the hash
 */
public record HashResult(String hash, String hmacVersionId) {}
