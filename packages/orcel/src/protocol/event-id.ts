import { createUlid } from "#shared/ulid.js";

/** Prefix stamped on every orcel session stream event id. */
export const KAFNT_ID_PREFIX = "evt_";

/**
 * Mints the id carried on one session stream event's `meta.id`:
 * {@link KAFNT_ID_PREFIX} followed by a ULID.
 *
 * See `#shared/ulid.js` for the ordering guarantee — it holds within a
 * process, not across the separate steps of one session.
 */
export function createEventId(): string {
  return `${KAFNT_ID_PREFIX}${createUlid()}`;
}
