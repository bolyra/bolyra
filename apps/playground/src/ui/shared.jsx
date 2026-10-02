import { useState } from 'react';
import { track } from '../core/usage.js';

export function Field({ label, hint, children }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
      {hint ? <span className="field-hint">{hint}</span> : null}
    </label>
  );
}

export function Status({ kind, children }) {
  return <span className={`status status-${kind}`}>{children}</span>;
}

export function CodeBlock({ text, tall }) {
  return <pre className={`code${tall ? ' code-tall' : ''}`}><code>{text}</code></pre>;
}

export function CopyButton({ text, label = 'Copy' }) {
  const [state, setState] = useState('idle');
  const onClick = async () => {
    track('copy_clicked');
    try { await navigator.clipboard.writeText(text); setState('done'); }
    catch { setState('failed'); }
    setTimeout(() => setState('idle'), 1500);
  };
  return <button type="button" className="btn btn-ghost" onClick={onClick}>{state === 'done' ? 'Copied' : state === 'failed' ? 'Select and copy manually' : label}</button>;
}

/** Builds the blob on click so nothing is created until the user asks. */
export function DownloadButton({ text, filename, label, mime = 'application/octet-stream' }) {
  const onClick = () => {
    track('export_clicked');
    const url = URL.createObjectURL(new Blob([text], { type: mime }));
    const a = document.createElement('a');
    a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return <button type="button" className="btn btn-ghost" onClick={onClick} data-download={filename}>{label}</button>;
}
