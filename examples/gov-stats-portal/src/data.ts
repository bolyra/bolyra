/** Mock public statistics. Every figure is invented; the shape is what a portal might serve. */
export const PUBLIC_STATS = {
  source: 'mock',
  note: 'Invented figures for a demonstration portal. Not real statistics.',
  dataset: 'quarterly-service-volumes',
  period: '2026-Q2',
  rows: [
    { service: 'general-practice-consultations', count: 1_234_567 },
    { service: 'pharmacy-dispensings', count: 2_345_678 },
    { service: 'diagnostic-imaging', count: 345_678 },
  ],
};
