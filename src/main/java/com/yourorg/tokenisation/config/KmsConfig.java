package com.yourorg.tokenisation.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;

import java.net.URI;

/**
 * Spring configuration for the AWS KMS client.
 *
 * <p>Only created when {@code kms.provider=aws}. When {@code kms.provider=local-dev},
 * no KMS client bean is created — {@link com.yourorg.tokenisation.kms.LocalDevKmsAdapter}
 * performs all key operations locally without any AWS SDK dependency.
 */
@Configuration
@ConditionalOnProperty(name = "kms.provider", havingValue = "aws")
public class KmsConfig {

    /**
     * Creates an AWS KMS client. When {@code kms.aws.endpoint-override} is set the client
     * points to that URL instead of real AWS — used for LocalStack in local/CI environments.
     *
     * @param awsRegion        the AWS region; from {@code kms.aws.region}
     * @param endpointOverride optional endpoint URL (e.g. {@code http://localhost:4566} for LocalStack)
     * @return a configured {@link KmsClient}
     */
    @Bean
    public KmsClient kmsClient(
            @Value("${kms.aws.region}") String awsRegion,
            @Value("${kms.aws.endpoint-override:#{null}}") String endpointOverride) {
        KmsClientBuilder builder = KmsClient.builder()
                .region(Region.of(awsRegion));
        if (endpointOverride != null && !endpointOverride.isBlank()) {
            builder.endpointOverride(URI.create(endpointOverride));
        }
        return builder.build();
    }
}
