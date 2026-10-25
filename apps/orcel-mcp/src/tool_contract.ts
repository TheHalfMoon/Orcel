import type { OAuthScope } from "./oauth_authorization.js";

/**
 * SG-000065 authoritative tool metadata contract.
 *
 * Every canonical MCP tool has exactly one entry. Registration,
 * annotations, profile-filtered discovery, the OAuth scope matrix, and the
 * local-only list are all derived from this record, and contract tests pin
 * it against the tool sources, the orceld remote-session scope table, and
 * the parity inventory. Discovery filtering is never authorization: orceld,
 * the remote-session lease, and the OAuth ceilings still enforce every call.
 *
 * Annotation semantics:
 * - `readOnlyHint`: the tool never changes local state.
 * - `destructiveHint`: the tool may delete or overwrite existing user data
 *   (file content, clipboard content, or arbitrary effects of a registered
 *   executable). Purely additive or index-only changes are not destructive.
 * - `idempotentHint`: repeating the call with the same arguments has no
 *   further effect.
 * - `openWorldHint`: the tool reaches beyond the local machine (network
 *   peers) or runs a registered executable whose effects are not modelled.
 */

export type ToolSurfaceProfile = "core" | "desktop_structured" | "browser_structured";

export type EffectClass =
  | "read"
  | "preview"
  | "write"
  | "destructive"
  | "execute"
  | "network"
  | "desktop_observe"
  | "desktop_capture"
  | "desktop_control"
  | "clipboard";

export type ApprovalClass = "none" | "SOFT" | "STRONG";

export interface ToolAnnotations {
  readonly title: string;
  readonly readOnlyHint: boolean;
  readonly destructiveHint: boolean;
  readonly idempotentHint: boolean;
  readonly openWorldHint: boolean;
}

export interface ToolContractEntry {
  readonly capability: string;
  readonly operation: string;
  readonly effect: EffectClass;
  readonly approval: ApprovalClass;
  /** Remote OAuth scopes, or "local_only" for tools no remote path may call. */
  readonly remote: readonly OAuthScope[] | "local_only";
  readonly outputBound: string;
  readonly annotations: ToolAnnotations;
}

const read = (title: string): ToolAnnotations => ({
  title,
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
});

const change = (
  title: string,
  hints: { destructive: boolean; idempotent: boolean; openWorld?: boolean }
): ToolAnnotations => ({
  title,
  readOnlyHint: false,
  destructiveHint: hints.destructive,
  idempotentHint: hints.idempotent,
  openWorldHint: hints.openWorld ?? false
});

const READ: readonly OAuthScope[] = ["orcel.read"];
const WRITE: readonly OAuthScope[] = ["orcel.write"];
const EXECUTE: readonly OAuthScope[] = ["orcel.execute"];

export const TOOL_CONTRACT: Readonly<Record<string, ToolContractEntry>> = {
  system_status: {
    capability: "system.status", operation: "get", effect: "read", approval: "none", remote: READ,
    outputBound: "fixed-size daemon status object", annotations: read("Orcel status")
  },
  workspace_get: {
    capability: "workspace.get", operation: "get", effect: "read", approval: "none", remote: READ,
    outputBound: "fixed-size workspace metadata", annotations: read("Get workspace")
  },
  fs_stat: {
    capability: "fs.stat", operation: "stat", effect: "read", approval: "none", remote: READ,
    outputBound: "fixed-size metadata for one path", annotations: read("File metadata")
  },
  fs_list: {
    capability: "fs.list", operation: "list", effect: "read", approval: "none", remote: READ,
    outputBound: "at most 5000 entries of one directory, truncation reported", annotations: read("List directory")
  },
  fs_read: {
    capability: "fs.read", operation: "read", effect: "read", approval: "none", remote: READ,
    outputBound: "one UTF-8 file of at most 1 MiB", annotations: read("Read file")
  },
  fs_search: {
    capability: "fs.search", operation: "search", effect: "read", approval: "none", remote: READ,
    outputBound: "at most 200 matches over at most 2000 files of at most 512 KiB", annotations: read("Search files")
  },
  fs_read_range: {
    capability: "fs.read_range", operation: "read", effect: "read", approval: "none", remote: READ,
    outputBound: "at most 2000 lines and 1 MiB of one UTF-8 file", annotations: read("Read line range")
  },
  fs_find: {
    capability: "fs.find", operation: "find", effect: "read", approval: "none", remote: READ,
    outputBound: "at most 500 results, depth 16, 20000 entries visited", annotations: read("Find files")
  },
  git_status: {
    capability: "git.status", operation: "status", effect: "read", approval: "none", remote: READ,
    outputBound: "at most 2 MiB of git output", annotations: read("Git status")
  },
  git_diff: {
    capability: "git.diff", operation: "diff", effect: "read", approval: "none", remote: READ,
    outputBound: "at most 2 MiB of git output", annotations: read("Git diff")
  },
  git_log: {
    capability: "git.log", operation: "log", effect: "read", approval: "none", remote: READ,
    outputBound: "at most 100 commits within 2 MiB of git output", annotations: read("Git log")
  },
  fs_write_preview: {
    capability: "fs.write", operation: "preview", effect: "preview", approval: "none", remote: WRITE,
    outputBound: "digests and sizes for one file of at most 2 MiB", annotations: read("Preview file write")
  },
  git_fetch_preview: {
    capability: "git.fetch.preview", operation: "preview", effect: "preview", approval: "none", remote: WRITE,
    outputBound: "fixed-size local fetch plan", annotations: read("Preview git fetch")
  },
  git_push_preview: {
    capability: "git.push.preview", operation: "preview", effect: "preview", approval: "none", remote: WRITE,
    outputBound: "fixed-size local push plan", annotations: read("Preview git push")
  },
  fs_write: {
    capability: "fs.write", operation: "write", effect: "write", approval: "SOFT", remote: WRITE,
    outputBound: "evidence only; writes at most 2 MiB", annotations: change("Write file", { destructive: true, idempotent: true })
  },
  fs_mkdir: {
    capability: "fs.mkdir", operation: "mkdir", effect: "write", approval: "SOFT", remote: WRITE,
    outputBound: "evidence only", annotations: change("Create directory", { destructive: false, idempotent: false })
  },
  fs_move: {
    capability: "fs.move", operation: "move", effect: "write", approval: "SOFT", remote: WRITE,
    outputBound: "evidence only", annotations: change("Move or rename", { destructive: false, idempotent: false })
  },
  fs_edit: {
    capability: "fs.edit", operation: "edit", effect: "write", approval: "SOFT", remote: WRITE,
    outputBound: "evidence only; files of at most 2 MiB", annotations: change("Edit file", { destructive: true, idempotent: false })
  },
  fs_remove: {
    capability: "fs.remove", operation: "remove", effect: "destructive", approval: "STRONG", remote: WRITE,
    outputBound: "evidence only", annotations: change("Remove file or empty directory", { destructive: true, idempotent: false })
  },
  git_branch_create: {
    capability: "git.branch.create", operation: "create", effect: "write", approval: "SOFT", remote: WRITE,
    outputBound: "evidence only", annotations: change("Create git branch", { destructive: false, idempotent: false })
  },
  git_stage: {
    capability: "git.stage", operation: "stage", effect: "write", approval: "SOFT", remote: WRITE,
    outputBound: "evidence only; at most 128 paths", annotations: change("Git stage", { destructive: false, idempotent: true })
  },
  git_unstage: {
    capability: "git.unstage", operation: "unstage", effect: "write", approval: "SOFT", remote: WRITE,
    outputBound: "evidence only; at most 128 paths", annotations: change("Git unstage", { destructive: false, idempotent: true })
  },
  git_commit: {
    capability: "git.commit", operation: "commit", effect: "write", approval: "SOFT", remote: WRITE,
    outputBound: "evidence only; message at most 8 KiB", annotations: change("Git commit", { destructive: false, idempotent: false })
  },
  git_fetch: {
    capability: "git.fetch", operation: "fetch", effect: "network", approval: "SOFT", remote: WRITE,
    outputBound: "evidence only", annotations: change("Git fetch", { destructive: false, idempotent: true, openWorld: true })
  },
  git_push: {
    capability: "git.push", operation: "push", effect: "network", approval: "SOFT", remote: WRITE,
    outputBound: "evidence only", annotations: change("Git push", { destructive: false, idempotent: true, openWorld: true })
  },
  process_spawn: {
    capability: "process.spawn", operation: "spawn", effect: "execute", approval: "SOFT", remote: EXECUTE,
    outputBound: "requested stdout of at most 16 MiB and stderr of at most 4 MiB",
    annotations: change("Run registered program", { destructive: true, idempotent: false, openWorld: true })
  },
  desktop_cursor_get: {
    capability: "desktop.cursor", operation: "get", effect: "desktop_observe", approval: "none", remote: "local_only",
    outputBound: "fixed-size cursor position and screen geometry", annotations: read("Read desktop cursor")
  },
  desktop_element_invoke: {
    capability: "uia.element", operation: "invoke", effect: "desktop_control", approval: "SOFT", remote: "local_only",
    outputBound: "bounded semantic action evidence", annotations: change("Invoke desktop element", { destructive: true, idempotent: false })
  },
  desktop_element_scroll: {
    capability: "uia.element", operation: "scroll", effect: "desktop_control", approval: "SOFT", remote: "local_only",
    outputBound: "bounded semantic action evidence; at most 20 scroll ticks", annotations: change("Scroll desktop element", { destructive: true, idempotent: false })
  },
  desktop_element_select: {
    capability: "uia.element", operation: "select", effect: "desktop_control", approval: "SOFT", remote: "local_only",
    outputBound: "bounded semantic action evidence", annotations: change("Select desktop element", { destructive: true, idempotent: false })
  },
  desktop_element_set_value: {
    capability: "uia.element", operation: "set_value", effect: "desktop_control", approval: "SOFT", remote: "local_only",
    outputBound: "bounded semantic action evidence; value at most 1024 characters", annotations: change("Set desktop element value", { destructive: true, idempotent: false })
  },
  desktop_element_toggle: {
    capability: "uia.element", operation: "toggle", effect: "desktop_control", approval: "SOFT", remote: "local_only",
    outputBound: "bounded semantic action evidence", annotations: change("Toggle desktop element", { destructive: true, idempotent: false })
  },
  desktop_input_execute: {
    capability: "desktop.input", operation: "execute", effect: "desktop_control", approval: "SOFT", remote: "local_only",
    outputBound: "fixed-size execution result for one bounded input action", annotations: change("Execute desktop input", { destructive: true, idempotent: false })
  },
  desktop_window_action: {
    capability: "desktop.window", operation: "action", effect: "desktop_control", approval: "SOFT", remote: "local_only",
    outputBound: "fixed-size result for one exact-window lifecycle action", annotations: change("Control desktop window", { destructive: true, idempotent: false })
  },
  desktop_window_capture: {
    capability: "uia.screenshot", operation: "capture", effect: "desktop_capture", approval: "SOFT", remote: "local_only",
    outputBound: "one exact-window bounded capture; oversized payloads fail closed", annotations: read("Capture desktop window")
  },
  desktop_window_list: {
    capability: "uia.window", operation: "list", effect: "desktop_observe", approval: "none", remote: "local_only",
    outputBound: "at most 64 windows within 64 KiB", annotations: read("List desktop windows")
  },
  desktop_window_tree: {
    capability: "uia.tree", operation: "observe", effect: "desktop_observe", approval: "none", remote: "local_only",
    outputBound: "depth 8 and at most 256 elements within 64 KiB", annotations: read("Read window UI tree")
  },
  clipboard_read: {
    capability: "clipboard", operation: "read", effect: "clipboard", approval: "SOFT", remote: "local_only",
    outputBound: "one text sample of at most 64 KiB", annotations: read("Read clipboard")
  },
  clipboard_write: {
    capability: "clipboard", operation: "write", effect: "clipboard", approval: "SOFT", remote: "local_only",
    outputBound: "evidence only; places at most 64 KiB",
    annotations: change("Write clipboard", { destructive: true, idempotent: true })
  },
  web_fetch: {
    capability: "network", operation: "fetch", effect: "network", approval: "SOFT", remote: "local_only",
    outputBound: "one response body of at most 1 MiB",
    annotations: { title: "Fetch public HTTPS URL", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  },
  web_search: {
    capability: "search", operation: "query", effect: "network", approval: "SOFT", remote: "local_only",
    outputBound: "at most 10 untrusted results; titles 300 and snippets 1000 characters; provider response at most 512 KiB",
    annotations: { title: "Search the web", readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: true }
  },
  // SG-000127 slice 3: the SG-000126 report task, local transports only.
  report_start: {
    capability: "report", operation: "start", effect: "read", approval: "none", remote: "local_only",
    outputBound: "one task id and 1..8 labelled untrusted source texts, each within the 1 MiB provider read limit",
    annotations: { ...read("Start local report task"), idempotentHint: false }
  },
  report_preview: {
    capability: "report", operation: "preview", effect: "preview", approval: "none", remote: "local_only",
    outputBound: "the destination, size and SHA-256 of one proposed report",
    annotations: { ...read("Preview local report"), idempotentHint: false }
  },
  report_commit: {
    capability: "report", operation: "commit", effect: "write", approval: "SOFT", remote: "local_only",
    outputBound: "evidence only; creates one UTF-8 report of at most 256 KiB, never overwriting",
    annotations: change("Create local report", { destructive: false, idempotent: false })
  },
  // SG-000120 RJ-03: the resume summary of the caller's own report task.
  task_resume_summary: {
    capability: "report", operation: "resume_summary", effect: "read", approval: "none", remote: "local_only",
    outputBound: "the task's bounded steps as kinds, outcomes and keyed fingerprints, the checks for unknown steps, and a note of at most 4 KiB; never source or report text",
    annotations: read("Read local task resume summary")
  },
  // SG-000108 slice 3c: the live isolated browser, `browser_structured` only.
  browser_page_open: {
    capability: "browser.page", operation: "open", effect: "read", approval: "none", remote: "local_only",
    outputBound: "one page id and its generation",
    annotations: { ...read("Open isolated browser page"), idempotentHint: false }
  },
  browser_navigate: {
    capability: "browser.navigation", operation: "navigate", effect: "network", approval: "SOFT", remote: "local_only",
    outputBound: "the committed URL, status and generation",
    annotations: change("Navigate isolated browser page", { destructive: false, idempotent: false, openWorld: true })
  },
  browser_observe: {
    capability: "browser.snapshot", operation: "observe", effect: "read", approval: "none", remote: "local_only",
    outputBound: "one frame of node identities and keyed digests; no page text",
    annotations: read("Observe isolated browser page")
  },
  browser_click: {
    capability: "browser.dom", operation: "click", effect: "network", approval: "SOFT", remote: "local_only",
    outputBound: "the opened URL, status and generation",
    annotations: change("Open a link on isolated browser page", { destructive: false, idempotent: false, openWorld: true })
  },
  browser_download_preview: {
    capability: "browser.download", operation: "preview", effect: "preview", approval: "none", remote: "local_only",
    outputBound: "the link's origin, file name and digest, the folder and the file name; writes nothing",
    annotations: read("Preview isolated browser download")
  },
  browser_download: {
    capability: "browser.download", operation: "download", effect: "network", approval: "SOFT", remote: "local_only",
    outputBound: "the committed file's name, SHA-256 and size; at most the transfer bound written, create-only",
    annotations: change("Download from isolated browser page", { destructive: false, idempotent: false, openWorld: true })
  }
};

/**
 * SG-000067 per-tool security schemes, emitted as `_meta.securitySchemes`
 * on every transport. Every remotely mappable tool requires an OAuth 2
 * access token with exactly its contract scopes; local-only tools declare
 * none because no remote path may call them. No tool is anonymous.
 */
export function securitySchemesFor(
  name: string
): ReadonlyArray<{ readonly type: "oauth2"; readonly scopes: readonly OAuthScope[] }> | null {
  const remote = TOOL_CONTRACT[name]?.remote;
  if (remote === undefined || remote === "local_only") {
    return null;
  }
  return [{ type: "oauth2", scopes: [...remote] }];
}

/** Tools any remote path may map: every entry with remote OAuth scopes. */
export const REMOTE_TOOL_NAMES: readonly string[] = Object.keys(TOOL_CONTRACT).filter(
  (name) => TOOL_CONTRACT[name]?.remote !== "local_only"
);

/** Tools no remote path may call. */
export const LOCAL_ONLY_TOOL_NAMES: readonly string[] = Object.keys(TOOL_CONTRACT).filter(
  (name) => TOOL_CONTRACT[name]?.remote === "local_only"
);

/**
 * SG-000108 decision 6: the live browser MCP tools, served only under
 * `browser_structured`. They must equal `LIVE_BROWSER_SHAPES` in
 * `crates/orceld/src/profile_gate.rs` and `LIVE_BROWSER_MCP_TOOLS` in
 * `crates/orcel-browser-host/src/exposure.rs` (browser-exposure.test.ts).
 * Slice 3c: six of SG-000079's qualified shapes; fill and uploads stay
 * model-only.
 */
export const LIVE_BROWSER_TOOLS: readonly string[] = Object.freeze([
  "browser_page_open",
  "browser_navigate",
  "browser_observe",
  "browser_click",
  "browser_download_preview",
  "browser_download"
]);

/**
 * `desktop_structured`, listed explicitly instead of every contract key, so
 * that adding a tool to the contract (a browser tool in particular) never
 * widens it.
 */
export const DESKTOP_STRUCTURED_TOOLS: readonly string[] = Object.freeze([
  "system_status",
  "workspace_get",
  "fs_stat",
  "fs_list",
  "fs_read",
  "fs_search",
  "fs_read_range",
  "fs_find",
  "git_status",
  "git_diff",
  "git_log",
  "fs_write_preview",
  "git_fetch_preview",
  "git_push_preview",
  "fs_write",
  "fs_mkdir",
  "fs_move",
  "fs_edit",
  "fs_remove",
  "git_branch_create",
  "git_stage",
  "git_unstage",
  "git_commit",
  "git_fetch",
  "git_push",
  "process_spawn",
  "desktop_cursor_get",
  "desktop_element_invoke",
  "desktop_element_scroll",
  "desktop_element_select",
  "desktop_element_set_value",
  "desktop_element_toggle",
  "desktop_input_execute",
  "desktop_window_action",
  "desktop_window_capture",
  "desktop_window_list",
  "desktop_window_tree",
  "clipboard_read",
  "clipboard_write",
  "web_fetch",
  "web_search",
  "report_start",
  "report_preview",
  "report_commit",
  "task_resume_summary"
] as const);

/**
 * Exact profile membership. `core` is the remote ceiling; local transports
 * serve `desktop_structured`, which adds the local-only tools, or, only when
 * local configuration selects it, `browser_structured`, which adds the live
 * browser tools. The `developer` and `coordinate_fallback` profiles from the
 * plan are not mapped and deny.
 */
export const SURFACE_PROFILES: Readonly<Record<ToolSurfaceProfile, readonly string[]>> = {
  core: REMOTE_TOOL_NAMES,
  desktop_structured: DESKTOP_STRUCTURED_TOOLS,
  browser_structured: Object.freeze([...DESKTOP_STRUCTURED_TOOLS, ...LIVE_BROWSER_TOOLS])
};

/** The environment variable a local MCP client configuration sets. */
export const TOOL_SURFACE_PROFILE_ENV = "ORCEL_TOOL_SURFACE_PROFILE";

/** The profiles a local transport may serve. */
export const LOCAL_TOOL_SURFACE_PROFILES: readonly ToolSurfaceProfile[] = Object.freeze([
  "desktop_structured",
  "browser_structured"
] as const);

/**
 * The local transport's profile, from its local configuration only (the
 * MCP client's server launch environment, which the user writes; never a
 * tool argument or a remote value). Unset selects `desktop_structured`;
 * anything that is not a local profile fails startup.
 */
export function localProfileFromConfig(value: string | undefined): ToolSurfaceProfile {
  if (value === undefined || value === "") {
    return "desktop_structured";
  }
  if ((LOCAL_TOOL_SURFACE_PROFILES as readonly string[]).includes(value)) {
    return value as ToolSurfaceProfile;
  }
  throw new Error(`TOOL_SURFACE_DENIED: ${TOOL_SURFACE_PROFILE_ENV} names no local tool surface profile`);
}

export function profileTools(profile: string): ReadonlySet<string> {
  if (!Object.hasOwn(SURFACE_PROFILES, profile)) {
    throw new Error(`tool surface profile is not mapped: ${profile}`);
  }
  return new Set(SURFACE_PROFILES[profile as ToolSurfaceProfile]);
}

/**
 * Provider-specific differences. In v0.2 every known remote provider shares
 * the `core` ceiling and no provider gains or loses a tool relative to
 * another; local transports serve `desktop_structured` regardless of the
 * configured provider kind, which is metadata and never proof of identity.
 * A remote connection from an unknown provider kind maps to no profile.
 */
export const REMOTE_PROVIDER_PROFILES: Readonly<Record<string, ToolSurfaceProfile>> = {
  generic: "core",
  openai: "core",
  anthropic: "core",
  mistral: "core",
  codex: "core"
};

export function remoteProfileForProvider(providerKind: string): ToolSurfaceProfile | null {
  return Object.hasOwn(REMOTE_PROVIDER_PROFILES, providerKind) ? (REMOTE_PROVIDER_PROFILES[providerKind] ?? null) : null;
}
