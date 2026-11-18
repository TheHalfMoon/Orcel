// SG-000135 OB-04: what keeps a page off the person's desktop, in Shadow
// and Visible sessions alike.
//
// - The system clipboard and other permissions: the engine's context is
//   told to grant no permission at all (Playwright `grantPermissions([])`,
//   which the engine applies as "grant these and reject all others" for
//   every origin). A page's asynchronous clipboard read and write calls then
//   reject, even right after an approved click gave it a user activation, as
//   do notification, geolocation and the other permission prompts. If the
//   engine refuses, the launch fails (fail closed). The legacy
//   `document.execCommand("copy")` path is not governed by permissions; that
//   residual is recorded in
//   docs/orcel/implementation-readiness/prep/OB04_MODES_PROFILES.md.
// - Native file dialogs: every page of the session has a file-chooser
//   listener, so Playwright intercepts the chooser and the engine never
//   opens an OS dialog. The chooser is left unanswered (denied); uploads go
//   only through the host's own SG-000026 path (`setInputFiles`).

/// The part of a browser context the permission guard uses.
export interface PermissionContext {
  grantPermissions(permissions: string[]): Promise<void>;
}

/// Grant no permission to any page of `context` (every other one is then
/// rejected by the engine); throws when the engine refuses.
export async function denyDesktopPermissions(context: PermissionContext): Promise<void> {
  await context.grantPermissions([]);
}

/// The part of a page the chooser guard uses.
export interface ChooserPage {
  on(event: "filechooser", listener: () => void): unknown;
}

/// Intercept every file chooser of `page`: no native dialog, no files.
export function interceptFileChoosers(page: ChooserPage): void {
  page.on("filechooser", () => {
    // Deliberately unanswered: the chooser is denied.
  });
}
