import pc from "#compiled/picocolors/index.js";

import { resolveInstalledPackageInfo } from "#internal/application/package.js";

export const KAF_WORDMARK = "kaf";

/**
 * The boot banner shared by every CLI command that announces itself: the kaf
 * badge plus the installed version. Init prints it before its progress row.
 */
export function kafCliBanner(): string {
  const { version } = resolveInstalledPackageInfo();
  return `${pc.bgBlack(pc.white(`☰${KAF_WORDMARK} `))} ${pc.dim(`v${version}`)}`;
}

/**
 * The unstyled wordmark-and-version tag (`☰kaf  v0.24.5`) — the boot banner's
 * plain-text form. The dev TUI dims it as its parting line on teardown.
 */
export function kafVersionTag(): string {
  const { version } = resolveInstalledPackageInfo();
  return `☰${KAF_WORDMARK}  v${version}`;
}
