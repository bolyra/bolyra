import { Router, Request, Response } from 'express';
import { query } from './db';

export const credentialsRouter = Router();

/**
 * POST /v1/credentials
 * Register or update an agent credential.
 */
credentialsRouter.post('/v1/credentials', async (req: Request, res: Response) => {
  try {
    const { credential, metadata } = req.body;

    if (!credential || !credential.commitment) {
      res.status(400).json({ error: 'Missing credential or commitment' });
      return;
    }

    const commitment = String(credential.commitment);

    await query(
      `INSERT INTO agent_credentials (commitment, credential_json, metadata, status, created_at, updated_at)
       VALUES ($1, $2, $3, 'active', now(), now())
       ON CONFLICT (commitment) DO UPDATE
       SET credential_json = $2,
           metadata = $3,
           status = 'active',
           updated_at = now(),
           revoked_at = NULL`,
      [commitment, JSON.stringify(credential), JSON.stringify(metadata ?? {})],
    );

    res.json({ commitment, status: 'active' });
  } catch (err) {
    console.error('POST /v1/credentials error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /v1/credentials/:commitment
 * Retrieve an active credential by commitment.
 */
credentialsRouter.get('/v1/credentials/:commitment', async (req: Request, res: Response) => {
  try {
    const { commitment } = req.params;

    const result = await query(
      `SELECT credential_json FROM agent_credentials
       WHERE commitment = $1 AND status = 'active'`,
      [commitment],
    );

    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Credential not found' });
      return;
    }

    res.json({ credential: result.rows[0].credential_json });
  } catch (err) {
    console.error('GET /v1/credentials/:commitment error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * DELETE /v1/credentials/:commitment
 * Soft-revoke a credential.
 */
credentialsRouter.delete('/v1/credentials/:commitment', async (req: Request, res: Response) => {
  try {
    const { commitment } = req.params;

    const result = await query(
      `UPDATE agent_credentials
       SET status = 'revoked', revoked_at = now(), updated_at = now()
       WHERE commitment = $1 AND status = 'active'
       RETURNING commitment`,
      [commitment],
    );

    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Credential not found' });
      return;
    }

    res.json({ commitment, status: 'revoked' });
  } catch (err) {
    console.error('DELETE /v1/credentials/:commitment error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
