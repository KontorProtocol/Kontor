/**
 * The serialization primitive each `Account` impl uses to implement
 * `runExclusive` — a minimal in-house async mutex on a promise chain.
 *
 * Lives under `account/` because the lock is conceptually per-account:
 * it protects whatever broadcast-mutating sequence touches this
 * account's funding pool. Two transports binding the same Account
 * share its lock, so a `submit` on transport A serializes naturally
 * against an `offer` on transport B.
 *
 * Body of `runExclusive` is attached to the tail of the chain; the
 * next caller awaits the prior tail (success or failure), guaranteeing
 * one body at a time. No deps.
 */
export class AccountLock {
  private chain: Promise<void> = Promise.resolve();

  async runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const prev = this.chain;
    let release!: () => void;
    this.chain = new Promise<void>((resolve) => {
      release = resolve;
    });
    try {
      await prev;
      return await fn();
    } finally {
      release();
    }
  }
}
