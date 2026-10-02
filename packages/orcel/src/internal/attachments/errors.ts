/**
 * Discriminator for {@link OrcelAttachmentError}.
 *
 * Today the only literal ever produced in the codebase is
 * `"resolver-threw"`. The union remains a discriminated type so future
 * producers can broaden it intentionally rather than as an accident of
 * a string parameter that drifted.
 */
type OrcelAttachmentErrorKind = "resolver-threw";

/**
 * Input shape for {@link OrcelAttachmentError}. Separated from the class
 * constructor so callers can build the options object inline and TS
 * can check the `kind` / `message` pair without a positional
 * constructor signature.
 */
interface OrcelAttachmentErrorInput {
  readonly kind: OrcelAttachmentErrorKind;
  readonly message: string;
  readonly adapterKind?: string;
  readonly cause?: unknown;
}

/**
 * Error surfaced when an attachment resolver fails to produce bytes for
 * an {@link AttachmentRef}.
 *
 * Channels can inspect the `.kind` discriminator to decide whether to
 * drop the attachment and continue the turn (the default posture for
 * every kind today) or fail the whole delivery (future strict mode).
 * `.message` crosses into model-visible input when the attachment is
 * dropped, so it must not contain URLs, credentials, or verbatim upstream
 * error text. Preserve private diagnostics on `.cause` instead.
 * The original failure, when there is one, is preserved on `.cause` so
 * observability can surface the upstream error without losing context.
 */
export class OrcelAttachmentError extends Error {
  readonly kind: OrcelAttachmentErrorKind;
  readonly adapterKind?: string;
  override readonly cause?: unknown;

  constructor(input: OrcelAttachmentErrorInput) {
    super(input.message);
    this.name = "OrcelAttachmentError";
    this.kind = input.kind;
    if (input.adapterKind !== undefined) {
      this.adapterKind = input.adapterKind;
    }
    if (input.cause !== undefined) {
      this.cause = input.cause;
    }
  }
}
