import { renderCliFooter, renderCliHeader, renderPanel, renderSectionTitle, renderStatus } from './branding';

export function renderExample(): string {
  return [
    renderCliHeader('Threat Intelligence Command Interface'),
    '',
    renderSectionTitle('Latest Findings'),
    renderPanel(
      [
        renderStatus('success', 'Tenant telemetry synchronized.'),
        renderStatus('warning', '2 assets missing EDR heartbeat.'),
        renderStatus('error', '1 control validation failed.')
      ].join('\n'),
      'Ops Snapshot'
    ),
    renderCliFooter()
  ].join('\n');
}
