BEGIN;

ALTER TABLE tasks DROP COLUMN IF EXISTS cancel_attempted;

COMMIT;
