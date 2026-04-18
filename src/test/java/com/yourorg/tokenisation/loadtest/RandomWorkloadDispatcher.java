package com.yourorg.tokenisation.loadtest;

import java.util.random.RandomGenerator;

/**
 * Weighted random selector for mixed-workload load tests.
 *
 * <p>Distributes operation types according to configurable integer weights.
 * The weights do not need to sum to any particular value — they are normalised
 * internally to a cumulative distribution from which {@link #nextOperation()}
 * samples uniformly.
 *
 * <p>Example — 40/20/35/5 distribution:
 * <pre>{@code
 * var dispatcher = new RandomWorkloadDispatcher(40, 20, 35, 5);
 * Operation op = dispatcher.nextOperation(); // proportional random selection
 * }</pre>
 */
public class RandomWorkloadDispatcher {

    /**
     * The operation types that can be selected by this dispatcher.
     */
    public enum Operation {
        /** {@code POST /api/v1/tokens} with {@code ONE_TIME} token type. */
        TOKENISE_ONE_TIME,
        /** {@code POST /api/v1/tokens} with {@code RECURRING} token type. */
        TOKENISE_RECURRING,
        /** {@code GET /api/v1/tokens/{token}} — full PAN recovery. */
        DETOKENISE,
        /** {@code GET /api/v1/tokens/{token}} — lightweight existence check (404 is also a "response"). */
        STATUS_CHECK
    }

    private final int[] cumulativeWeights;
    private final int totalWeight;
    private final RandomGenerator random;

    /**
     * Creates a dispatcher with the given weights for each operation type.
     *
     * <p>Weights are integers; relative proportions matter, not absolute values.
     *
     * @param tokeniseOneTimeWeight   relative weight for ONE_TIME tokenisation
     * @param tokeniseRecurringWeight relative weight for RECURRING tokenisation
     * @param detokeniseWeight        relative weight for detokenisation
     * @param statusCheckWeight       relative weight for status check
     */
    public RandomWorkloadDispatcher(int tokeniseOneTimeWeight,
                                    int tokeniseRecurringWeight,
                                    int detokeniseWeight,
                                    int statusCheckWeight) {
        this.random = RandomGenerator.getDefault();
        int[] weights = {
            tokeniseOneTimeWeight,
            tokeniseRecurringWeight,
            detokeniseWeight,
            statusCheckWeight
        };
        this.cumulativeWeights = new int[weights.length];
        int cumulative = 0;
        for (int i = 0; i < weights.length; i++) {
            cumulative += weights[i];
            cumulativeWeights[i] = cumulative;
        }
        this.totalWeight = cumulative;
    }

    /**
     * Returns the next operation type, sampled from the configured weight distribution.
     *
     * @return one of the {@link Operation} values, proportional to the configured weights
     */
    public Operation nextOperation() {
        int roll = random.nextInt(totalWeight);
        Operation[] ops = Operation.values();
        for (int i = 0; i < cumulativeWeights.length; i++) {
            if (roll < cumulativeWeights[i]) {
                return ops[i];
            }
        }
        return Operation.TOKENISE_ONE_TIME; // unreachable, satisfies compiler
    }
}
