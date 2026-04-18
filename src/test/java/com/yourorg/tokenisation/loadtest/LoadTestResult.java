package com.yourorg.tokenisation.loadtest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;

/**
 * Immutable result record for a single load test run.
 *
 * <p>After each load test completes, call {@link #writeToFile()} to persist the result
 * as a pretty-printed JSON document in {@code target/load-test-results/}. Results are
 * retained across builds until the directory is cleaned, enabling comparison across runs.
 *
 * @param testName           human-readable test identifier (e.g. {@code "LT-T-10K"})
 * @param totalRequests      total number of requests submitted
 * @param concurrency        number of concurrent virtual threads
 * @param wallClockMs        elapsed wall-clock time from first submission to last completion
 * @param p50Ms              50th-percentile (median) per-request latency in milliseconds
 * @param p95Ms              95th-percentile per-request latency in milliseconds
 * @param p99Ms              99th-percentile per-request latency in milliseconds
 * @param maxMs              maximum observed per-request latency in milliseconds
 * @param errorCount         number of requests that returned a non-2xx status or threw an exception
 * @param heapGrowthMb       heap growth from before to after the test run, in megabytes
 * @param recordedAt         wall-clock timestamp when this result was captured
 */
public record LoadTestResult(
        String testName,
        int totalRequests,
        int concurrency,
        long wallClockMs,
        long p50Ms,
        long p95Ms,
        long p99Ms,
        long maxMs,
        long errorCount,
        long heapGrowthMb,
        Instant recordedAt
) {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .findAndRegisterModules()
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    /**
     * Serialises this result to JSON and writes it to
     * {@code target/load-test-results/{testName}-{epochSecond}.json}.
     *
     * <p>The output directory is created if it does not exist. Write failures are
     * logged to {@code System.err} but do not affect the test outcome.
     */
    public void writeToFile() {
        try {
            Path dir = Paths.get("target", "load-test-results");
            Files.createDirectories(dir);
            String safeName = testName.replaceAll("[^a-zA-Z0-9_\\-]", "_");
            Path file = dir.resolve(safeName + "-" + recordedAt.getEpochSecond() + ".json");
            MAPPER.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), this);
        } catch (IOException e) {
            System.err.println("Warning: could not write load test result for "
                    + testName + ": " + e.getMessage());
        }
    }
}
