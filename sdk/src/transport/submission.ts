import { hex } from "@scure/base";
import { Transaction } from "@scure/btc-signer";
import { sha256 } from "@scure/btc-signer/utils.js";
import { TransportError } from "../errors.js";
import type { FundingDelta, FundingLease } from "../funding.js";

export interface BroadcastObservation {
  txid: string;
  wtxid: string;
  status: "accepted" | "unknown";
  reason: string | null;
}

/** Positive Bitcoin observations, not a promise of confirmation or finality. */
export interface BroadcastReport {
  outcome: "accepted" | "partial" | "unknown";
  transactions: BroadcastObservation[];
}

export interface SignedTransaction {
  readonly hex: string;
  readonly txid: string;
  readonly wtxid: string;
}

type SubmissionState<T> =
  | { kind: "prepared" }
  | { kind: "publishing"; task: Promise<T>; report?: BroadcastReport }
  | { kind: "uncertain" | "accepted"; report: BroadcastReport }
  | { kind: "abandoned"; report?: BroadcastReport };

export class SubmissionError<T = unknown> extends TransportError {
  override name = "SubmissionError";
  constructor(
    readonly recovery: PendingSubmission<T>,
    cause?: unknown,
  ) {
    super(
      "transaction publication is unresolved; recover the original signed submission",
      {
        cause: cause instanceof Error ? cause : undefined,
        docsPath: "/sdk/funding",
      },
    );
  }
}

/** Retained by HttpTransport until accepted or explicitly abandoned. */
export class PendingSubmission<T = unknown> {
  readonly transactions: readonly SignedTransaction[];
  private state: SubmissionState<T> = { kind: "prepared" };
  private readonly delta: FundingDelta;

  constructor(
    raw: readonly string[],
    readonly value: T,
    private readonly lease: FundingLease,
    delta: FundingDelta,
    private readonly request: (
      mode: "broadcast" | "reconcile",
      raw: string[],
    ) => Promise<unknown>,
    private readonly completed: () => void,
  ) {
    if (!raw.length)
      throw new TransportError("cannot publish an empty transaction package");
    this.transactions = Object.freeze(
      raw.map((encoded) => {
        const bytes = hex.decode(encoded);
        const transaction = Transaction.fromRaw(bytes, {
          disableScriptCheck: true,
          allowUnknownInputs: true,
          allowUnknownOutputs: true,
        });
        return Object.freeze({
          hex: hex.encode(bytes),
          txid: transaction.id,
          wtxid: hex.encode(sha256(sha256(bytes)).reverse()),
        });
      }),
    );
    this.delta = {
      spent: delta.spent.map((utxo) => ({ ...utxo })),
      change: delta.change.map((utxo) => ({ ...utxo })),
    };
  }

  get status(): SubmissionState<T>["kind"] {
    return this.state.kind;
  }

  get report(): BroadcastReport | undefined {
    return "report" in this.state && this.state.report
      ? {
          outcome: this.state.report.outcome,
          transactions: this.state.report.transactions.map((entry) => ({
            ...entry,
          })),
        }
      : undefined;
  }

  retry(): Promise<T> {
    return this.attempt("broadcast");
  }
  reconcile(): Promise<T> {
    return this.attempt("reconcile");
  }

  /** Retire at-risk coins locally. This neither revokes signatures nor cancels Bitcoin transactions. */
  abandon(): void {
    if (this.state.kind === "publishing")
      throw new TransportError(
        "wait for the pending submission operation before abandoning",
      );
    if (this.state.kind === "accepted" || this.state.kind === "abandoned")
      return;
    const report = this.report;
    const accepted = new Set(
      report?.transactions
        .filter((entry) => entry.status === "accepted")
        .map((entry) => entry.txid),
    );
    // delta.change already excludes every output consumed anywhere in the
    // signed package, including children whose relay outcome is unknown.
    this.lease.settle({
      spent: this.delta.spent,
      change: this.delta.change.filter((utxo) => accepted.has(utxo.txid)),
    });
    this.state = { kind: "abandoned", report };
    this.completed();
  }

  private validate(value: unknown): BroadcastReport {
    const report = value as BroadcastReport | null;
    if (
      !report ||
      !Array.isArray(report.transactions) ||
      report.transactions.length !== this.transactions.length
    )
      throw new TransportError("invalid broadcast report");
    const transactions = report.transactions.map((entry, index) => {
      const expected = this.transactions[index]!;
      if (
        !entry ||
        entry.txid !== expected.txid ||
        entry.wtxid !== expected.wtxid ||
        (entry.status !== "accepted" && entry.status !== "unknown") ||
        (entry.reason !== null && typeof entry.reason !== "string")
      )
        throw new TransportError(
          "broadcast report does not match the signed package",
        );
      return { ...entry };
    });
    const accepted = transactions.filter(
      (entry) => entry.status === "accepted",
    ).length;
    const outcome =
      accepted === transactions.length
        ? "accepted"
        : accepted
          ? "partial"
          : "unknown";
    if (outcome !== report.outcome)
      throw new TransportError("inconsistent broadcast report");
    return { outcome, transactions };
  }

  private attempt(mode: "broadcast" | "reconcile"): Promise<T> {
    if (this.state.kind === "accepted") return Promise.resolve(this.value);
    if (this.state.kind === "abandoned")
      return Promise.reject(
        new TransportError(
          "submission was abandoned; use the preserved bytes for wallet recovery",
        ),
      );
    if (this.state.kind === "publishing") return this.state.task;
    const previous = this.report;
    const task = Promise.resolve().then(async () => {
      let report: BroadcastReport;
      try {
        report = this.validate(
          await this.request(
            mode,
            this.transactions.map((tx) => tx.hex),
          ),
        );
      } catch (cause) {
        this.state = {
          kind: "uncertain",
          report: {
            outcome: "unknown",
            transactions: this.transactions.map((tx) => ({
              txid: tx.txid,
              wtxid: tx.wtxid,
              status: "unknown",
              reason: "publication could not be reconciled",
            })),
          },
        };
        throw new SubmissionError(this, cause);
      }
      this.state = { kind: "uncertain", report };
      if (report.outcome !== "accepted") throw new SubmissionError(this);
      try {
        this.lease.settle(this.delta);
      } catch (cause) {
        throw new SubmissionError(this, cause);
      }
      this.state = { kind: "accepted", report };
      this.completed();
      return this.value;
    });
    this.state = { kind: "publishing", task, report: previous };
    return task;
  }
}
