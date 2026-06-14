CREATE TABLE IF NOT EXISTS agent_credentials (
  commitment TEXT PRIMARY KEY,
  credential_json JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  metadata JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_credentials_status ON agent_credentials(status);
