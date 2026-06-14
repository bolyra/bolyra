import { Request, Response, NextFunction } from 'express';

export function apiKeyAuth(req: Request, res: Response, next: NextFunction): void {
  // Skip auth for health checks
  if (req.path === '/health') {
    next();
    return;
  }

  const apiKey = process.env.REGISTRY_API_KEY;
  if (!apiKey) {
    res.status(500).json({ error: 'Server misconfigured: no API key set' });
    return;
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing or malformed Authorization header' });
    return;
  }

  const token = authHeader.slice(7);
  if (token !== apiKey) {
    res.status(401).json({ error: 'Invalid API key' });
    return;
  }

  next();
}
