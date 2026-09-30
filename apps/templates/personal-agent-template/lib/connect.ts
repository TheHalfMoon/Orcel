/**
 * Issuer passed to Vercel Connect for user-scoped tokens.
 * Must match Kaf's `appSession()` authenticator in `agent/channels/kaf.ts`.
 */
export const CONNECT_USER_ISSUER = "app";

/** Vercel Connect connector UID — keep in sync with `server/connectors.ts`. */
export const GITHUB_CONNECTOR = "github/personal-agent";
