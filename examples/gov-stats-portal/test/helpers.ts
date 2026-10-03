import { spawn, type ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as http from 'node:http';

/** A portal running as a CHILD process with its own HOME (its own local nonce store). */
export interface ChildPortal { port: number; home: string; stop(): Promise<void> }

export async function startChildPortal(audience: string, extraEnv: Record<string, string> = {}): Promise<ChildPortal> {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'gsp-home-'));
  const env: Record<string, string | undefined> = { ...process.env, HOME: home, PORTAL_AUDIENCE: audience, ...extraEnv };
  delete env.BOLYRA_TRUSTED_ROOTS;
  const main = path.join(__dirname, '..', 'src', 'portal-main.js');
  const child: ChildProcess = spawn(process.execPath, [main], { env, stdio: ['ignore', 'pipe', 'inherit'] });
  const port = await new Promise<number>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('portal did not start within 15 s')), 15_000);
    let buf = '';
    child.stdout!.on('data', (d) => { buf += d.toString(); const m = /\{"port":(\d+)\}/.exec(buf); if (m) { clearTimeout(timer); resolve(Number(m[1])); } });
    child.on('exit', (code) => { clearTimeout(timer); reject(new Error(`portal exited early with ${code}`)); });
  });
  return {
    port, home,
    stop: () => new Promise<void>((resolve) => { child.once('exit', () => { fs.rmSync(home, { recursive: true, force: true }); resolve(); }); child.kill('SIGTERM'); setTimeout(() => child.kill('SIGKILL'), 5_000).unref(); }),
  };
}

export interface Reply { status: number; headers: http.IncomingHttpHeaders; body: any; text: string }
export function request(port: number, method: string, path: string, headers: Record<string, string> = {}): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers, timeout: 60_000 }, (res) => {
      let text = '';
      res.on('data', (d) => { text += d; });
      res.on('end', () => { let body: any = null; try { body = JSON.parse(text); } catch { /* not json */ } resolve({ status: res.statusCode ?? 0, headers: res.headers, body, text }); });
    });
    req.on('timeout', () => { req.destroy(new Error('request timeout')); });
    req.on('error', reject);
    req.end();
  });
}
