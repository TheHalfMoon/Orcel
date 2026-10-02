// Thin ESM re-export of the `@vercel/sdk` model helpers the dev TUI uses to
// read and patch a project's trusted-sources policy. Vendoring this slice
// instead of importing `@vercel/sdk` directly keeps the SDK and its Zod out
// of orcel's dist tree: the bundle imports orcel's single vendored Zod.
export { updateProjectTrustedSourcesFromJSON } from "@vercel/sdk/models/updateprojectblock.js";
export { trustedSourcesToJSON } from "@vercel/sdk/models/updateprojectprojectsbranchmatcher.js";
