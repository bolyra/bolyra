import { Component, useState } from 'react';
import { track } from '../core/usage.js';
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

/** A render error in one view must never unmount the other views. */
class ViewBoundary extends Component {
  constructor(props) { super(props); this.state = { error: null }; }
  static getDerivedStateFromError(error) { return { error }; }
  render() {
    if (this.state.error) return <div className="results" data-view-error><strong>This view hit a rendering error:</strong> <code>{String(this.state.error && this.state.error.message)}</code>. The other tabs are unaffected; reload the page to reset this one.</div>;
    return this.props.children;
  }
}

export function App({ pg }) {
  const fromHash = typeof location !== 'undefined' ? location.hash.slice(1) : '';
  const initial = TABS.some((t) => t.id === fromHash) ? fromHash : 'verify';
  const [tab, setTab] = useState(initial);
  return (
    <div className="app">
      <div className="tab-bar" role="tablist">
        {TABS.map((t) => (
          <button key={t.id} type="button" role="tab" aria-selected={tab === t.id} className={`tab-btn${tab === t.id ? ' active' : ''}`} onClick={() => { track(`tab_${t.id === 'wire' ? 'evc' : t.id}`); setTab(t.id); }} data-tab={t.id}>{t.label}</button>
        ))}
      </div>
      {/* Both views stay mounted: the simulator's session (key, chain, log) must
          survive a tab switch. Only the explicit Reset action destroys it. */}
      <div hidden={tab !== 'verify'}><ViewBoundary><VerifyView pg={pg} /></ViewBoundary></div>
      <div hidden={tab !== 'simulate'}><ViewBoundary><SimulateView pg={pg} /></ViewBoundary></div>
      <div hidden={tab !== 'decode'}><ViewBoundary><DecodeView pg={pg} /></ViewBoundary></div>
      <div hidden={tab !== 'wire'}><ViewBoundary><WireView pg={pg} /></ViewBoundary></div>
    </div>
  );
}
