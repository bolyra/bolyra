/**
 * Receipt store — persistent receipt storage with indexing.
 *
 * Receipts are stored in ~/.bolyra/receipts/ as NDJSON files,
 * one per bolyra-run session. An index file tracks session metadata.
 *
 * Used by:
 *   bolyra run (writes receipts)
 *   bolyra replay last (reads latest session)
 *   bolyra replay <session-id> (reads specific session)
 *   bolyra dev from-receipt <session-id> (generates test fixtures)
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

const STORE_DIR = path.join(os.homedir(), '.bolyra', 'receipts');
const INDEX_FILE = path.join(STORE_DIR, 'index.json');

export interface SessionMeta {
  id: string;
  server: string;
  startedAt: string;
  receiptCount: number;
  allowCount: number;
  denyCount: number;
  policyFile?: string;
}

export interface ReceiptEntry {
  decision: 'allow' | 'deny';
  toolName?: string;
  did?: string;
  score?: number;
  reason?: string;
  timestamp?: string;
  permissionBitmask?: string;
}

function ensureDir(): void {
  fs.mkdirSync(STORE_DIR, { recursive: true });
}

function loadIndex(): SessionMeta[] {
  if (!fs.existsSync(INDEX_FILE)) return [];
  try {
    return JSON.parse(fs.readFileSync(INDEX_FILE, 'utf-8'));
  } catch {
    return [];
  }
}

function saveIndex(sessions: SessionMeta[]): void {
  ensureDir();
  fs.writeFileSync(INDEX_FILE, JSON.stringify(sessions, null, 2));
}

/** Create a new session and return its ID + write stream path. */
export function createSession(server: string, policyFile?: string): { id: string; filePath: string } {
  ensureDir();
  const id = `ses_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const filePath = path.join(STORE_DIR, `${id}.ndjson`);

  const sessions = loadIndex();
  sessions.push({
    id,
    server,
    startedAt: new Date().toISOString(),
    receiptCount: 0,
    allowCount: 0,
    denyCount: 0,
    policyFile,
  });
  saveIndex(sessions);

  // Create empty file
  fs.writeFileSync(filePath, '');

  return { id, filePath };
}

/** Append a receipt to a session file and update the index. */
export function appendReceipt(sessionId: string, receipt: ReceiptEntry): void {
  const filePath = path.join(STORE_DIR, `${sessionId}.ndjson`);
  fs.appendFileSync(filePath, JSON.stringify(receipt) + '\n');

  // Update index counts
  const sessions = loadIndex();
  const session = sessions.find(s => s.id === sessionId);
  if (session) {
    session.receiptCount++;
    if (receipt.decision === 'allow') session.allowCount++;
    if (receipt.decision === 'deny') session.denyCount++;
    saveIndex(sessions);
  }
}

/** Get the latest session metadata. */
export function getLatestSession(): SessionMeta | null {
  const sessions = loadIndex();
  return sessions.length > 0 ? sessions[sessions.length - 1] : null;
}

/** Get a session by ID. */
export function getSession(id: string): SessionMeta | null {
  const sessions = loadIndex();
  return sessions.find(s => s.id === id) ?? null;
}

/** List all sessions. */
export function listSessions(): SessionMeta[] {
  return loadIndex();
}

/** Read all receipts from a session. */
export function readSessionReceipts(sessionId: string): ReceiptEntry[] {
  const filePath = path.join(STORE_DIR, `${sessionId}.ndjson`);
  if (!fs.existsSync(filePath)) return [];

  const content = fs.readFileSync(filePath, 'utf-8');
  const receipts: ReceiptEntry[] = [];
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const obj = JSON.parse(trimmed);
      if (obj.decision) receipts.push(obj);
    } catch { /* skip */ }
  }
  return receipts;
}

/** Get the file path for a session's receipts. */
export function getSessionFilePath(sessionId: string): string {
  return path.join(STORE_DIR, `${sessionId}.ndjson`);
}

/** Get the store directory path. */
export function getStoreDir(): string {
  return STORE_DIR;
}
