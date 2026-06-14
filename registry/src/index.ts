import express from 'express';
import { credentialsRouter } from './credentials';
import { apiKeyAuth } from './auth';

const app = express();
app.use(express.json());
app.use(apiKeyAuth);
app.use(credentialsRouter);

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3100;
app.listen(PORT, () => console.log(`Bolyra Registry listening on :${PORT}`));
