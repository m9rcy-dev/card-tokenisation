package com.yourorg.tokenisation;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the Card Tokenisation System.
 *
 * <p>On startup, {@code KeyRingInitialiser} loads all active and rotating KEK versions
 * from KMS into the in-memory key ring before the application begins serving traffic.
 * Scheduling and distributed lock configuration lives in {@code SchedulingConfig}.
 */
@SpringBootApplication
public class TokenisationApplication {

    /**
     * Launches the Spring Boot application.
     *
     * @param args command-line arguments forwarded to Spring
     */
    public static void main(String[] args) {
        SpringApplication.run(TokenisationApplication.class, args);
    }
}
