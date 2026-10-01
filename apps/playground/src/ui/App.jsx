import { useState } from 'react';
import { VerifyView } from './VerifyView.jsx';
import { SimulateView } from './SimulateView.jsx';
import { DecodeView } from './DecodeView.jsx';
import { WireView } from './WireView.jsx';

const TABS = [
  { id: 'verify', label: 'Verify receipts' },
  { id: 'simulate', label: 'Simulate spend policy' },
  { id: 'decode', label: 'Decode a 402' },
  { id: 'wire', label: 'EVC wire shapes' },
];

export function App({ pg }) {
  const fromHash = typeof location !== 'undefined' ? location.hash.slice(1) : '';
  const initial = TABS.some((t) => t.id === fromHash) ? fromHash : 'verify';
  const [tab, setTab] = useState(initial);
  return (
    <div className="app">
      <div className="tab-bar" role="tablist">
        {TABS.map((t) => (
          <button key={t.id} type="button" role="tab" aria-selected={tab === t.id} className={`tab-btn${tab === t.id ? ' active' : ''}`} onClick={() => setTab(t.id)} data-tab={t.id}>{t.label}</button>
        ))}
      </div>
      {/* Both views stay mounted: the simulator's session (key, chain, log) must
          survive a tab switch. Only the explicit Reset action destroys it. */}
      <div hidden={tab !== 'verify'}><VerifyView pg={pg} /></div>
      <div hidden={tab !== 'simulate'}><SimulateView pg={pg} /></div>
      <div hidden={tab !== 'decode'}><DecodeView pg={pg} /></div>
      <div hidden={tab !== 'wire'}><WireView pg={pg} /></div>
    </div>
  );
}
