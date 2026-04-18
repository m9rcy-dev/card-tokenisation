package com.yourorg.tokenisation.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

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
     * Creates an AWS KMS client configured for the specified region.
     *
     * <p>Credentials are resolved from the default AWS credential provider chain:
     * environment variables → system properties → IAM role (EC2/ECS/Lambda).
     * Access keys must never be hardcoded.
     *
     * @param awsRegion the AWS region where the KMS key resides; from {@code kms.aws.region}
     * @return a configured {@link KmsClient} ready for KMS API calls
     */
    @Bean
    public KmsClient kmsClient(@Value("${kms.aws.region}") String awsRegion) {
        return KmsClient.builder()
                .region(Region.of(awsRegion))
                .build();
    }
}
