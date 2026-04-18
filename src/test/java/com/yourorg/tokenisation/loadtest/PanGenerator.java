package com.yourorg.tokenisation.loadtest;

import java.security.SecureRandom;

/**
 * Generates cryptographically random Luhn-valid 16-digit PANs for load testing.
 *
 * <p>Generated PANs begin with {@code "4"} (a Visa IIN prefix) and satisfy the
 * Luhn algorithm. They are structurally valid but are not real card numbers —
 * they will not pass issuer-side validation.
 *
 * <p>Uses {@link SecureRandom} so that the generated PAN space is unpredictable
 * enough to avoid de-duplication hits between ONE_TIME tokenisation requests
 * in the same load test run.
 */
public final class PanGenerator {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private PanGenerator() {}

    /**
     * Generates a random Luhn-valid 16-digit Visa-prefixed PAN.
     *
     * @return a 16-character string of decimal digits
     */
    public static String generateVisa16() {
        // Build a 15-digit partial PAN: leading "4" + 14 random digits
        StringBuilder sb = new StringBuilder(16);
        sb.append('4');
        for (int i = 0; i < 14; i++) {
            sb.append(SECURE_RANDOM.nextInt(10));
        }
        // Append the Luhn check digit to complete the 16-digit PAN
        sb.append(luhnCheckDigit(sb.toString()));
        return sb.toString();
    }

    /**
     * Computes the Luhn check digit for a partial PAN (without the trailing check digit).
     *
     * <p>The algorithm processes the digits from right to left, doubling every other digit
     * starting with the rightmost. If doubling produces a number greater than 9, subtract 9.
     * The check digit is {@code (10 - (sum % 10)) % 10}.
     *
     * @param partial the partial PAN without the check digit
     * @return the single check digit (0–9) to append
     */
    static int luhnCheckDigit(String partial) {
        int sum = 0;
        boolean doubleIt = true; // rightmost digit of partial is doubled first
        for (int i = partial.length() - 1; i >= 0; i--) {
            int digit = partial.charAt(i) - '0';
            if (doubleIt) {
                digit *= 2;
                if (digit > 9) {
                    digit -= 9;
                }
            }
            sum += digit;
            doubleIt = !doubleIt;
        }
        return (10 - (sum % 10)) % 10;
    }
}
