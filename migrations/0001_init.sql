-- migrations/0001_create_table.sql
CREATE TABLE IF NOT EXISTS github_webhooks (
    id SERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    received_at TIMESTAMP DEFAULT now()
);
