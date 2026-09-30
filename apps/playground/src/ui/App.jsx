import { useState } from 'react';
import { VerifyView } from './VerifyView.jsx';
import { SimulateView } from './SimulateView.jsx';

const TABS = [
  { id: 'verify', label: 'Verify receipts' },
  { id: 'simulate', label: 'Simulate spend policy' },
];

export function App({ pg }) {
  const initial = typeof location !== 'undefined' && location.hash === '#simulate' ? 'simulate' : 'verify';
  const [tab, setTab] = useState(initial);
  return (
    <div className="app">
      <div className="tab-bar" role="tablist">
        {TABS.map((t) => (
          <button key={t.id} type="button" role="tab" aria-selected={tab === t.id} className={`tab-btn${tab === t.id ? ' active' : ''}`} onClick={() => setTab(t.id)} data-tab={t.id}>{t.label}</button>
        ))}
      </div>
      {tab === 'verify' ? <VerifyView pg={pg} /> : <SimulateView pg={pg} />}
    </div>
  );
}
