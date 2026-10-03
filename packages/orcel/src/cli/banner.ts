import pc from "#compiled/picocolors/index.js";

import { resolveInstalledPackageInfo } from "#internal/application/package.js";

export const ORCEL_WORDMARK = "orcel";

/**
 * The boot banner shared by every CLI command that announces itself: the orcel
 * badge plus the installed version. Init prints it before its progress row.
 */
export function orcelCliBanner(): string {
  const { version } = resolveInstalledPackageInfo();
  return `${pc.bgBlack(pc.white(`☰${ORCEL_WORDMARK} `))} ${pc.dim(`v${version}`)}`;
}

/**
 * The unstyled wordmark-and-version tag (`☰orcel  v0.24.5`) — the boot banner's
 * plain-text form. The dev TUI dims it as its parting line on teardown.
 */
export function orcelVersionTag(): string {
  const { version } = resolveInstalledPackageInfo();
  return `☰${ORCEL_WORDMARK}  v${version}`;
}
