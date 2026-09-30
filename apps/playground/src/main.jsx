import { PLAYGROUND } from './core/index.js';
import { createRoot } from 'react-dom/client';
import { App } from './ui/App.jsx';

if (typeof document !== 'undefined') {
  const el = document.getElementById('app');
  if (el) createRoot(el).render(<App pg={PLAYGROUND} />);
}
