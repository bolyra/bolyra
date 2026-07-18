/**
 * ANSI escape code helpers for colored terminal output.
 * No external dependencies (no chalk).
 */

const ESC = '\x1b[';

export const green = (s: string): string => `${ESC}32m${s}${ESC}0m`;
export const red = (s: string): string => `${ESC}31m${s}${ESC}0m`;
export const cyan = (s: string): string => `${ESC}36m${s}${ESC}0m`;
export const yellow = (s: string): string => `${ESC}33m${s}${ESC}0m`;
export const dim = (s: string): string => `${ESC}2m${s}${ESC}0m`;
export const bold = (s: string): string => `${ESC}1m${s}${ESC}0m`;

export const CHECK = green('✓');
export const CROSS = red('✗');

export function header(title: string): void {
  console.log();
  console.log(bold(`--- ${title} ---`));
}

export function line(label: string, value: string): void {
  console.log(`  ${dim(label.padEnd(18))} ${value}`);
}
