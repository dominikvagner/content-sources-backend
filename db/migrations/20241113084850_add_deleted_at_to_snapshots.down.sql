BEGIN;

ALTER TABLE snapshots DROP COLUMN IF EXISTS deleted_at;

COMMIT;
