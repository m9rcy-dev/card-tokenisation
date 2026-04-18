package com.yourorg.tokenisation.loadtest;

import com.yourorg.tokenisation.AbstractIntegrationTest;
import org.junit.jupiter.api.Tag;
import org.springframework.test.context.ActiveProfiles;

import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Base class for all load tests.
 *
 * <p>Extends {@link AbstractIntegrationTest} to reuse the shared Testcontainers
 * PostgreSQL container, the {@code @DynamicPropertySource} datasource override,
 * and the test data seeder bean. Activates the {@code "load-test"} Spring profile
 * (in addition to the inherited {@code "test"} profile) so that
 * {@code application-load-test.yml} applies its performance-tuning overrides:
 * a larger HikariCP pool, {@code synchronous_commit = off}, disabled rate limits,
 * and suppressed SQL logging.
 *
 * <p>All load test subclasses are tagged {@code @Tag("load")} so they are excluded
 * from the standard {@code mvn test} run and only execute when the Maven
 * {@code load-tests} profile is active:
 * <pre>{@code
 * JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn test -P load-tests
 * }</pre>
 *
 * <h3>Utilities</h3>
 * <ul>
 *   <li>{@link #buildVirtualThreadExecutor} — creates a fixed-size virtual-thread pool.
 *   <li>{@link #awaitCompletion} — shuts down the pool and waits for all tasks.
 *   <li>{@link #captureHeapMb} — returns current heap usage after requesting GC.
 *   <li>{@link #computeStats} — sorts a latency array and returns p50/p95/p99/max.
 * </ul>
 */
@ActiveProfiles("load-test")
@Tag("load")
public abstract class AbstractLoadTest extends AbstractIntegrationTest {

    /**
     * Creates a fixed-size executor backed by virtual threads.
     *
     * <p>Virtual threads (JEP 444 / Java 21) park rather than block OS threads,
     * making them well-suited for high-concurrency HTTP load generation without
     * requiring a proportionally large OS thread pool.
     *
     * @param concurrency the number of concurrent virtual threads
     * @return a configured {@link ExecutorService}
     */
    protected ExecutorService buildVirtualThreadExecutor(int concurrency) {
        return Executors.newFixedThreadPool(
                concurrency,
                Thread.ofVirtual().name("load-vt-", 0).factory());
    }

    /**
     * Shuts down the executor and blocks until all submitted tasks complete or the
     * timeout elapses.
     *
     * @param executor       the executor to drain
     * @param timeoutSeconds maximum seconds to wait; a reasonable default is {@code 600}
     * @throws AssertionError if the timeout elapses before completion
     */
    protected void awaitCompletion(ExecutorService executor, long timeoutSeconds) {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(timeoutSeconds, TimeUnit.SECONDS)) {
                throw new AssertionError(
                        "Load test executor did not complete within " + timeoutSeconds + "s");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError("Load test interrupted", e);
        }
    }

    /**
     * Captures the current heap usage in megabytes.
     *
     * <p>Calls {@link System#gc()} before measurement to reduce noise from pending
     * garbage. Because GC is not deterministic, this is an approximation — use the
     * difference between before/after captures to measure growth, not the absolute value.
     *
     * @return heap usage in MB (total memory minus free memory)
     */
    protected long captureHeapMb() {
        System.gc();
        Runtime rt = Runtime.getRuntime();
        return (rt.totalMemory() - rt.freeMemory()) / (1024L * 1024L);
    }

    /**
     * Sorts the latency array in-place and computes p50, p95, p99, and max.
     *
     * <p>The array is sorted as a side effect. Call this once after all tasks complete;
     * do not pass the array to this method while tasks are still updating it.
     *
     * @param latencies raw per-request latency samples in milliseconds
     * @return immutable stats record
     */
    protected LatencyStats computeStats(long[] latencies) {
        Arrays.sort(latencies);
        return new LatencyStats(
                percentileFromSorted(latencies, 50),
                percentileFromSorted(latencies, 95),
                percentileFromSorted(latencies, 99),
                latencies[latencies.length - 1]);
    }

    private long percentileFromSorted(long[] sorted, double percentile) {
        int index = (int) Math.ceil(percentile / 100.0 * sorted.length) - 1;
        return sorted[Math.max(0, index)];
    }

    /**
     * Latency statistics computed from a sorted sample array.
     *
     * @param p50 50th percentile (median) in milliseconds
     * @param p95 95th percentile in milliseconds
     * @param p99 99th percentile in milliseconds
     * @param max maximum observed latency in milliseconds
     */
    public record LatencyStats(long p50, long p95, long p99, long max) {}
}
