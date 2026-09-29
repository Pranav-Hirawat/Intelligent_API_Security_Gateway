BEGIN;

ALTER TABLE adaptive_settings DROP COLUMN IF EXISTS file_config;
ALTER TABLE adaptive_settings DROP COLUMN IF EXISTS source;

COMMIT;
