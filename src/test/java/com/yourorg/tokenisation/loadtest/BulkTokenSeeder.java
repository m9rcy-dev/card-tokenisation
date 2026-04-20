package com.yourorg.tokenisation.loadtest;

import com.yourorg.tokenisation.crypto.AesGcmCipher;
import com.yourorg.tokenisation.crypto.EncryptResult;
import com.yourorg.tokenisation.crypto.InMemoryKeyRing;
import com.yourorg.tokenisation.crypto.KeyMaterial;
import com.yourorg.tokenisation.crypto.PanHasher;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * JDBC-based bulk token seeder for high-volume rotation load tests.
 *
 * <p>Seeds {@code token_vault} rows using real AES-256-GCM encryption so every record is
 * genuinely detokenisable via the production service after rotation. The HTTP API is intentionally
 * bypassed because seeding 100K–1M tokens via REST would itself take many minutes.
 *
 * <h3>Per-record operation</h3>
 * <ol>
 *   <li>Generate a Luhn-valid PAN via {@link PanGenerator#generateVisa16()}.
 *   <li>Encrypt it via {@link AesGcmCipher#encrypt(byte[], byte[])} using the active KEK.
 *       The cipher generates a fresh DEK and wraps it — no manual DEK handling required.
 *   <li>Compute the HMAC-SHA256 pan hash for de-duplication via {@link PanHasher#hash(String)}.
 *   <li>Accumulate into a chunk and flush to PostgreSQL via
 *       {@link JdbcTemplate#batchUpdate(String, List)} when the chunk is full.
 * </ol>
 *
 * <p>The active KEK is copied once before the loop and zeroed in a {@code finally} block,
 * consistent with the production key-material handling discipline.
 *
 * <p><strong>Thread safety:</strong> This class is not thread-safe. Call it from a single
 * thread (typically a {@code @BeforeEach} setup method).
 */
@Component
public class BulkTokenSeeder {

    private static final String INSERT_SQL = """
            INSERT INTO token_vault (
                token_id, token, encrypted_pan, iv, auth_tag,
                encrypted_dek, key_version_id, pan_hash, merchant_id,
                token_type, card_scheme, last_four, expiry_month, expiry_year,
                created_at, expires_at, is_active, record_version
            ) VALUES (?,?,?,?,?, ?,?::uuid,?,?, ?,?,?,?,?, ?,?,?,?)
            """;

    private final JdbcTemplate jdbc;
    private final AesGcmCipher cipher;
    private final InMemoryKeyRing keyRing;
    private final PanHasher panHasher;

    public BulkTokenSeeder(JdbcTemplate jdbc,
                           AesGcmCipher cipher,
                           InMemoryKeyRing keyRing,
                           PanHasher panHasher) {
        this.jdbc = jdbc;
        this.cipher = cipher;
        this.keyRing = keyRing;
        this.panHasher = panHasher;
    }

    /**
     * Inserts {@code count} encrypted token vault rows for the given merchant.
     *
     * @param count      number of rows to insert
     * @param merchantId merchant scope for all seeded tokens
     * @param chunkSize  JDBC batch size; 1000 is a good default
     * @return array of token strings in insertion order — use these for post-rotation verification
     */
    public String[] seedTokens(int count, String merchantId, int chunkSize) {
        KeyMaterial active = keyRing.getActive();
        byte[] kek = active.copyKek();
        String[] tokens = new String[count];
        try {
            List<Object[]> chunk = new ArrayList<>(chunkSize);
            // Convert to java.sql.Timestamp once — PostgreSQL JDBC driver does not accept
            // java.time.Instant directly (even with Types.TIMESTAMP_WITH_TIMEZONE).
            Timestamp now = Timestamp.from(Instant.now());
            Timestamp expiresAt = Timestamp.from(Instant.now().plusSeconds(5L * 365 * 86400));

            for (int i = 0; i < count; i++) {
                String pan = PanGenerator.generateVisa16();
                byte[] panBytes = pan.getBytes(StandardCharsets.UTF_8);
                EncryptResult enc = cipher.encrypt(panBytes, kek);
                Arrays.fill(panBytes, (byte) 0);

                String panHash = panHasher.hash(pan);
                String token = "tok-" + UUID.randomUUID();
                tokens[i] = token;

                chunk.add(new Object[]{
                        UUID.randomUUID(),            // token_id
                        token,                        // token
                        enc.ciphertext(),             // encrypted_pan
                        enc.iv(),                     // iv
                        enc.authTag(),                // auth_tag
                        enc.encryptedDek(),           // encrypted_dek
                        active.keyVersionId(),        // key_version_id (cast ::uuid in SQL)
                        panHash,                      // pan_hash
                        merchantId,                   // merchant_id
                        "ONE_TIME",                   // token_type
                        "VISA",                       // card_scheme
                        pan.substring(pan.length() - 4), // last_four
                        (short) 12,                   // expiry_month
                        (short) 2029,                 // expiry_year
                        now,                          // created_at
                        expiresAt,                    // expires_at
                        true,                         // is_active
                        0                             // record_version
                });

                if (chunk.size() == chunkSize) {
                    flushChunk(chunk);
                    chunk.clear();
                }
            }
            if (!chunk.isEmpty()) {
                flushChunk(chunk);
            }
        } finally {
            Arrays.fill(kek, (byte) 0);
        }
        return tokens;
    }

    private void flushChunk(List<Object[]> rows) {
        jdbc.batchUpdate(INSERT_SQL, rows, rows.size(), (ps, row) -> {
            ps.setObject(1,  row[0]);                            // token_id UUID
            ps.setString(2,  (String) row[1]);                   // token
            ps.setBytes(3,   (byte[]) row[2]);                   // encrypted_pan
            ps.setBytes(4,   (byte[]) row[3]);                   // iv
            ps.setBytes(5,   (byte[]) row[4]);                   // auth_tag
            ps.setBytes(6,   (byte[]) row[5]);                   // encrypted_dek
            ps.setObject(7,  row[6], Types.OTHER);               // key_version_id ::uuid
            ps.setString(8,  (String) row[7]);                   // pan_hash
            ps.setString(9,  (String) row[8]);                   // merchant_id
            ps.setString(10, (String) row[9]);                   // token_type
            ps.setString(11, (String) row[10]);                  // card_scheme
            ps.setString(12, (String) row[11]);                  // last_four
            ps.setShort(13,  (short) row[12]);                   // expiry_month
            ps.setShort(14,  (short) row[13]);                   // expiry_year
            ps.setTimestamp(15, (Timestamp) row[14]);                // created_at (TIMESTAMPTZ)
            ps.setTimestamp(16, (Timestamp) row[15]);                // expires_at (TIMESTAMPTZ)
            ps.setBoolean(17, (boolean) row[16]);                // is_active
            ps.setInt(18,    (int) row[17]);                     // record_version
        });
    }
}
