package com.yourorg.tokenisation.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for the key rotation job and compliance policy.
 *
 * <p>Bound from the {@code rotation} namespace in {@code application.yml}:
 * <pre>
 * rotation:
 *   batch:
 *     cron: "0 *&#47;15 * * * *"
 *     size: 500
 *     emergency-size: 100
 *   compliance:
 *     max-key-age-days: 365
 * </pre>
 */
@Component
@ConfigurationProperties(prefix = "rotation")
public class RotationProperties {

    private Batch batch = new Batch();
    private Compliance compliance = new Compliance();

    /**
     * Returns the batch sub-properties (cron, batch sizes).
     *
     * @return batch configuration; never null
     */
    public Batch getBatch() {
        return batch;
    }

    /**
     * Sets the batch sub-properties.
     *
     * @param batch the batch configuration; must not be null
     */
    public void setBatch(Batch batch) {
        this.batch = batch;
    }

    /**
     * Returns the compliance sub-properties (max key age).
     *
     * @return compliance configuration; never null
     */
    public Compliance getCompliance() {
        return compliance;
    }

    /**
     * Sets the compliance sub-properties.
     *
     * @param compliance the compliance configuration; must not be null
     */
    public void setCompliance(Compliance compliance) {
        this.compliance = compliance;
    }

    /**
     * Batch re-encryption job configuration.
     */
    public static class Batch {

        /**
         * Cron expression for the scheduled rotation job.
         * Use {@code "-"} to disable the scheduler (e.g. in test profiles).
         */
        private String cron = "0 */15 * * * *";

        /**
         * Number of token vault records to re-encrypt per scheduled batch run.
         */
        private int size = 500;

        /**
         * Number of token vault records to re-encrypt per emergency batch run.
         * Smaller batches allow faster per-record processing during a compromise response.
         */
        private int emergencySize = 100;

        /**
         * Number of parallel virtual threads used to re-encrypt DEKs within a single batch.
         * Each thread gets its own {@code REQUIRES_NEW} transaction, so failures are isolated.
         * Must be ≤ {@code hikari.maximum-pool-size − 5} to leave headroom for background threads.
         */
        private int parallelism = 8;

        /**
         * Maximum number of batches processed in a single cron invocation.
         * {@code 0} means unlimited — the job drains all remaining records in one shot.
         * Set to a positive value to cap wall-clock time per cron tick (e.g. {@code 100}
         * batches × 500 records = 50,000 records per 15-minute window).
         */
        private int maxBatchesPerRun = 0;

        /**
         * Returns the cron expression.
         *
         * @return cron string; {@code "-"} if disabled
         */
        public String getCron() {
            return cron;
        }

        /**
         * Sets the cron expression.
         *
         * @param cron the cron expression
         */
        public void setCron(String cron) {
            this.cron = cron;
        }

        /**
         * Returns the normal batch size.
         *
         * @return number of records per scheduled batch
         */
        public int getSize() {
            return size;
        }

        /**
         * Sets the normal batch size.
         *
         * @param size the batch size; must be positive
         */
        public void setSize(int size) {
            this.size = size;
        }

        /**
         * Returns the emergency batch size.
         *
         * @return number of records per emergency batch
         */
        public int getEmergencySize() {
            return emergencySize;
        }

        /**
         * Sets the emergency batch size.
         *
         * @param emergencySize the emergency batch size; must be positive
         */
        public void setEmergencySize(int emergencySize) {
            this.emergencySize = emergencySize;
        }

        /**
         * Returns the number of parallel rewrap threads per batch.
         *
         * @return parallelism; default 8
         */
        public int getParallelism() {
            return parallelism;
        }

        /**
         * Sets the number of parallel rewrap threads per batch.
         *
         * @param parallelism must be positive; keep ≤ HikariCP pool size minus 5
         */
        public void setParallelism(int parallelism) {
            this.parallelism = parallelism;
        }

        /**
         * Returns the maximum number of batches per cron invocation.
         *
         * @return max batches; {@code 0} means unlimited
         */
        public int getMaxBatchesPerRun() {
            return maxBatchesPerRun;
        }

        /**
         * Sets the maximum batches per cron invocation.
         *
         * @param maxBatchesPerRun {@code 0} for unlimited; positive to cap per-tick work
         */
        public void setMaxBatchesPerRun(int maxBatchesPerRun) {
            this.maxBatchesPerRun = maxBatchesPerRun;
        }
    }

    /**
     * Compliance policy configuration.
     */
    public static class Compliance {

        /**
         * Maximum age (in days) before a key version must be rotated.
         * Defaults to 365 (annual rotation).
         */
        private int maxKeyAgeDays = 365;

        /**
         * Returns the maximum key age in days.
         *
         * @return max key age in days
         */
        public int getMaxKeyAgeDays() {
            return maxKeyAgeDays;
        }

        /**
         * Sets the maximum key age in days.
         *
         * @param maxKeyAgeDays the max age; must be positive
         */
        public void setMaxKeyAgeDays(int maxKeyAgeDays) {
            this.maxKeyAgeDays = maxKeyAgeDays;
        }
    }
}
