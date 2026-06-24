package com.yourorg.tokenisation.loadtest;

import com.yourorg.tokenisation.crypto.*;
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
 *   <li>Encrypt it via {@link AesGcmCipher#encrypt(byte[], byte[])} using the active DEK.
 *   <li>Compute the HMAC-SHA256 pan hash for de-duplication via {@link PanHasher#hash(String)}.
 *   <li>Accumulate into a chunk and flush to PostgreSQL via
 *       {@link JdbcTemplate#batchUpdate(String, List)} when the chunk is full.
 * </ol>
 *
 * <p>The active DEK is copied once before the loop and zeroed in a {@code finally} block,
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
                key_version_id, pan_hash,
                card_scheme, last_four, expiry_month, expiry_year,
                created_at, expires_at, is_active, record_version
            ) VALUES (?,?,?,?,?, ?::uuid,?, ?,?,?,?, ?,?,?,?)
            """;

    private final JdbcTemplate jdbc;
    private final AesGcmCipher cipher;
    private final InMemoryDekKeyRing dekRing;
    private final PanHasher panHasher;

    public BulkTokenSeeder(JdbcTemplate jdbc,
                           AesGcmCipher cipher,
                           InMemoryDekKeyRing dekRing,
                           PanHasher panHasher) {
        this.jdbc = jdbc;
        this.cipher = cipher;
        this.dekRing = dekRing;
        this.panHasher = panHasher;
    }

    /**
     * Inserts {@code count} encrypted token vault rows.
     *
     * @param count     number of rows to insert
     * @param chunkSize JDBC batch size; 1000 is a good default
     * @return array of token strings in insertion order — use these for post-rotation verification
     */
    public String[] seedTokens(int count, int chunkSize) {
        KeyMaterial active = dekRing.getActive();
        byte[] dek = active.copyDek();
        String[] tokens = new String[count];
        try {
            List<Object[]> chunk = new ArrayList<>(chunkSize);
            Timestamp now = Timestamp.from(Instant.now());
            Timestamp expiresAt = Timestamp.from(Instant.now().plusSeconds(5L * 365 * 86400));

            for (int i = 0; i < count; i++) {
                String pan = PanGenerator.generateVisa16();
                byte[] panBytes = pan.getBytes(StandardCharsets.UTF_8);
                EncryptResult enc = cipher.encrypt(panBytes, dek);
                Arrays.fill(panBytes, (byte) 0);

                String panHash = panHasher.hash(pan).hash();
                String token = UUID.randomUUID().toString();
                tokens[i] = token;

                chunk.add(new Object[]{
                        UUID.randomUUID(),            // token_id
                        token,                        // token
                        enc.ciphertext(),             // encrypted_pan
                        enc.iv(),                     // iv
                        enc.authTag(),                // auth_tag
                        active.keyVersionId(),        // key_version_id (cast ::uuid in SQL)
                        panHash,                      // pan_hash
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
            Arrays.fill(dek, (byte) 0);
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
            ps.setObject(6,  row[5], Types.OTHER);               // key_version_id ::uuid
            ps.setString(7,  (String) row[6]);                   // pan_hash
            ps.setString(8,  (String) row[7]);                   // card_scheme
            ps.setString(9,  (String) row[8]);                   // last_four
            ps.setShort(10,  (short)  row[9]);                   // expiry_month
            ps.setShort(11,  (short)  row[10]);                  // expiry_year
            ps.setTimestamp(12, (Timestamp) row[11]);            // created_at
            ps.setTimestamp(13, (Timestamp) row[12]);            // expires_at
            ps.setBoolean(14, (boolean) row[13]);                // is_active
            ps.setInt(15,    (int)    row[14]);                  // record_version
        });
    }
}
