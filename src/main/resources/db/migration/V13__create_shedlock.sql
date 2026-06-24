-- ShedLock distributed scheduler lock table.
-- Ensures that @Scheduled jobs (rotation batch, HMAC batch) run on exactly one pod
-- at a time in a multi-replica deployment (OpenShift, Kubernetes).
-- One row per named lock; lock_until is set by the acquiring pod and cleared on release.
CREATE TABLE IF NOT EXISTS shedlock (
    name       VARCHAR(64)              NOT NULL,
    lock_until TIMESTAMP WITH TIME ZONE NOT NULL,
    locked_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    locked_by  VARCHAR(255)             NOT NULL,
    CONSTRAINT pk_shedlock PRIMARY KEY (name)
);
