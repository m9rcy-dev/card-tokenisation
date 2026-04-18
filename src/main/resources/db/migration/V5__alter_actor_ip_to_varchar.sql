-- V5__alter_actor_ip_to_varchar.sql
--
-- Corrects the actor_ip column type from INET to VARCHAR(45).
--
-- The INET type in PostgreSQL requires a custom Hibernate type mapping.
-- Since actor_ip is stored purely for audit trail purposes and is never
-- queried with IP-specific operators (CIDR matching, containment), a
-- plain VARCHAR(45) is sufficient and avoids Hibernate schema validation
-- failures (Types#OTHER vs Types#VARCHAR mismatch).
--
-- IPv4 max length: 15 characters (255.255.255.255)
-- IPv6 max length: 45 characters (0000:0000:0000:0000:0000:0000:255.255.255.255)

ALTER TABLE token_audit_log
    ALTER COLUMN actor_ip TYPE VARCHAR(45) USING actor_ip::TEXT;
