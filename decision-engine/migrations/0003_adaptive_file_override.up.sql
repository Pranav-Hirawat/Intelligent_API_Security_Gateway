BEGIN;

-- Existing rows predate the source distinction. Preserve their active choice
-- as a console override; the decision engine records the real boot/file value
-- on its next start, so Revert has a known target without silently changing
-- enforcement during this migration.
ALTER TABLE adaptive_settings ADD COLUMN IF NOT EXISTS source TEXT;
ALTER TABLE adaptive_settings ADD COLUMN IF NOT EXISTS file_config JSONB;
UPDATE adaptive_settings
SET source = COALESCE(source, 'console'), file_config = COALESCE(file_config, config);
ALTER TABLE adaptive_settings ALTER COLUMN source SET DEFAULT 'file';
ALTER TABLE adaptive_settings ALTER COLUMN source SET NOT NULL;
ALTER TABLE adaptive_settings ALTER COLUMN file_config SET NOT NULL;

COMMIT;
