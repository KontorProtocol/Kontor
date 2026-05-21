/**
 * Error hierarchy for @kontor/sdk.
 *
 * `BaseError` is the rich base class — it carries a short summary, an
 * optional docs URL, the SDK version, and a cause chain (`walk()`) that
 * users can traverse to find the root issue. Production bug reports
 * benefit from the version stamp and docs URL.
 *
 * Subclasses cover the four broad failure surfaces:
 *
 *   - `TransportError`  — network / RPC issues (couldn't reach indexer,
 *                         bad HTTP status, malformed response, timeout)
 *   - `ContractError`   — contract execution failed (deterministic
 *                         revert, decode mismatch, unknown variant)
 *   - `SignerError`     — signing failed (no key, wrong key, wallet
 *                         rejected, PSBT mismatch)
 *   - `ChainError`      — configuration mismatch (account on wrong
 *                         network, missing UTXOs, fee estimation failed)
 *
 * Specific failures go in `details` on the subclass. We deliberately
 * don't sprout a leaf class per failure mode — that's the path the old
 * SDK took, and it produced 11 files of two-line constructors.
 */

const SDK_VERSION = "0.3.0";
const DEFAULT_DOCS_BASE = "https://docs.kontor.network";

export interface BaseErrorOptions {
  /** The underlying error, if this one is wrapping another. */
  cause?: Error;
  /** Free-form additional context (e.g. response body, RPC method). */
  details?: string;
  /** Optional path appended to the docs base URL. */
  docsPath?: string;
  /** Extra context lines printed below the headline. */
  metaMessages?: string[];
}

export class BaseError extends Error {
  readonly shortMessage: string;
  readonly details: string;
  readonly docsPath?: string;
  readonly metaMessages?: string[];
  readonly version: string = SDK_VERSION;
  override name = "BaseError";

  constructor(shortMessage: string, opts: BaseErrorOptions = {}) {
    const details =
      opts.cause instanceof BaseError
        ? opts.cause.details
        : (opts.cause?.message ?? opts.details ?? "");
    const docsPath =
      opts.cause instanceof BaseError
        ? (opts.cause.docsPath ?? opts.docsPath)
        : opts.docsPath;
    const docsUrl = docsPath ? `${DEFAULT_DOCS_BASE}${docsPath}` : undefined;

    const message = [
      shortMessage || "An error occurred.",
      "",
      ...(opts.metaMessages ? [...opts.metaMessages, ""] : []),
      ...(docsUrl ? [`Docs: ${docsUrl}`] : []),
      ...(details ? [`Details: ${details}`] : []),
      `Version: kontor-sdk@${SDK_VERSION}`,
    ].join("\n");

    super(message, opts.cause ? { cause: opts.cause } : undefined);
    this.shortMessage = shortMessage;
    this.details = details;
    this.docsPath = docsPath;
    this.metaMessages = opts.metaMessages;
  }

  /**
   * Walk the `cause` chain. With no predicate, returns the deepest
   * cause. With a predicate, returns the first link satisfying it (or
   * null if none match).
   */
  walk(): Error;
  walk(fn: (err: unknown) => boolean): Error | null;
  walk(fn?: (err: unknown) => boolean): Error | null {
    return walkCause(this, fn) as Error | null;
  }
}

function walkCause(
  err: unknown,
  fn?: (err: unknown) => boolean,
): unknown {
  if (fn?.(err)) return err;
  if (err && typeof err === "object" && "cause" in err && err.cause != null) {
    return walkCause(err.cause, fn);
  }
  return fn ? null : err;
}

export class TransportError extends BaseError {
  override name = "TransportError";
}

export class ContractError extends BaseError {
  override name = "ContractError";
}

export class SignerError extends BaseError {
  override name = "SignerError";
}

export class ChainError extends BaseError {
  override name = "ChainError";
}
