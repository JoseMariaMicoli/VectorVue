/*
VectorVue CLI Branding Utilities
*/

import boxen from 'boxen';
import chalk from 'chalk';
import gradient from 'gradient-string';

import { cliTheme } from './theme';

const metallic = gradient([cliTheme.colors.metallicStart, cliTheme.colors.metallicMid, cliTheme.colors.metallicEnd]);

export function renderCliHeader(subtitle = 'Operational Security Platform'): string {
  const title = chalk.bold(metallic('VECTORVUE'));
  const sub = chalk.hex(cliTheme.colors.textSecondary)(subtitle);
  return `${title}\n${sub}`;
}

export function renderSectionTitle(title: string): string {
  return chalk.bold.hex(cliTheme.colors.accent)(title);
}

export function renderStatus(status: 'success' | 'warning' | 'error', message: string): string {
  const color =
    status === 'success'
      ? cliTheme.colors.success
      : status === 'warning'
      ? cliTheme.colors.warning
      : cliTheme.colors.error;
  return `${chalk.bold.hex(color)(status.toUpperCase())} ${chalk.hex(cliTheme.colors.textPrimary)(message)}`;
}

export function renderPanel(content: string, title = 'VectorVue'): string {
  return boxen(content, {
    borderStyle: 'round',
    borderColor: cliTheme.colors.accent,
    backgroundColor: cliTheme.colors.bgPrimary,
    padding: { top: 0, right: 1, bottom: 0, left: 1 },
    title: chalk.hex(cliTheme.colors.textSecondary)(title),
    titleAlignment: 'left'
  });
}

export function renderCliFooter(): string {
  const line1 = chalk.hex(cliTheme.colors.textSecondary)(cliTheme.attribution.line1);
  const line2 = chalk.hex(cliTheme.colors.textSecondary)(cliTheme.attribution.line2);
  return `\n${line1}\n${line2}`;
}

export function renderCommandOutput(title: string, body: string): string {
  return [
    renderCliHeader(),
    '',
    renderSectionTitle(title),
    renderPanel(body, title),
    renderCliFooter()
  ].join('\n');
}
