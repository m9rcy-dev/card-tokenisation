package com.yourorg.tokenisation;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Entry point for the Card Tokenisation System.
 *
 * <p>On startup, {@code KeyRingInitialiser} loads all active and rotating KEK versions
 * from KMS into the in-memory key ring before the application begins serving traffic.
 * Scheduling is enabled here to support the key rotation batch job.
 */
@SpringBootApplication
@EnableScheduling
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
