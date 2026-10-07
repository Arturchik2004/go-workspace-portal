ALTER TABLE tasks
    ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'todo';

ALTER TABLE tasks
    DROP CONSTRAINT IF EXISTS tasks_status_check;

ALTER TABLE tasks
    ADD CONSTRAINT tasks_status_check CHECK (status IN ('todo', 'in_progress', 'done'));
