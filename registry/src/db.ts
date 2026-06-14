import { Pool, QueryResult } from 'pg';
import * as fs from 'fs';
import * as path from 'path';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

export async function query(text: string, params?: unknown[]): Promise<QueryResult> {
  return pool.query(text, params);
}

export async function migrate(): Promise<void> {
  const sql = fs.readFileSync(
    path.join(__dirname, '..', 'migrations', '001_credentials.sql'),
    'utf-8',
  );
  await pool.query(sql);
  console.log('Migration 001_credentials applied.');
}

export { pool };
