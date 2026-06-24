package com.yourorg.tokenisation.config;

import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider;
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Configures distributed scheduling via ShedLock.
 *
 * <p>ShedLock ensures that {@code @Scheduled} batch jobs (KEK rotation, HMAC rotation)
 * run on exactly one pod at a time in a multi-replica deployment. It acquires a row-level
 * lock in the {@code shedlock} table (created by V13 migration) before executing the job,
 * and releases it on completion or after {@code defaultLockAtMostFor} elapses.
 *
 * <p>The ring-refresh job ({@link com.yourorg.tokenisation.rotation.KeyRingRefreshJob})
 * intentionally does NOT use ShedLock — each pod must independently refresh its own
 * in-memory key ring.
 */
@Configuration
@EnableScheduling
@EnableSchedulerLock(defaultLockAtMostFor = "PT10M")
public class SchedulingConfig {

    @Bean
    public LockProvider lockProvider(JdbcTemplate jdbcTemplate) {
        return new JdbcTemplateLockProvider(
                JdbcTemplateLockProvider.Configuration.builder()
                        .withJdbcTemplate(jdbcTemplate)
                        .usingDbTime()
                        .build()
        );
    }
}
