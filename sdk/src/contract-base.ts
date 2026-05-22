/**
 * `ContractBase` — the hand-written runtime behind every codegen'd
 * `Contract`.
 *
 * Codegen emits typed method *signatures* that delegate here; the
 * encode → call → decode plumbing (and the attach/detach orchestration)
 * lives once, as real type-checked, testable code — not re-emitted as
 * source per contract. A generated proc method is a one-liner:
 *
 *     transfer(dst: HolderRef, amt: Decimal): Inst<…> {
 *       return this._proc("transfer", { dst: dst.toRaw(), … }, _decodeT12);
 *     }
 *
 * The generated subclass passes its embedded per-contract `Wit`
 * resource (that contract's WAVE codec) to `super`.
 */

import { Attachment } from "./attach.js";
import type { ContractAddress } from "./canonical/ContractAddress.js";
import type { Inst } from "./inst.js";
import type { KontorSession } from "./session.js";

/** The slice of the `Wit` WASM resource `ContractBase` consumes. */
interface WitCodec {
  encodeCall(fnName: string, argsJson: string): string;
  decodeResult(fnName: string, wave: string): string;
}

/** Maps a function's wire-JSON result to its typed value. */
type RawDecoder<T> = (raw: unknown) => T;

export abstract class ContractBase {
  /**
   * @param session  Bound execution surface.
   * @param address  The contract deployment.
   * @param wit      This contract's embedded WAVE codec.
   */
  constructor(
    protected readonly session: KontorSession,
    protected readonly address: ContractAddress,
    private readonly wit: WitCodec,
  ) {}

  /** WAVE-encode `args` (wire-JSON shape) into a call expression. */
  private callExpr(fnName: string, args: Record<string, unknown>): string {
    return this.wit.encodeCall(fnName, JSON.stringify(args));
  }

  /**
   * Wrap a raw-result decoder for use as an `Inst` decoder: WAVE result
   * → wire JSON → typed value. A `void`-returning function passes no
   * decoder; the wrapper then yields `undefined` (and is never invoked
   * anyway — the poller skips decoding an absent result value).
   */
  private wrapDecoder<T>(
    fnName: string,
    decode?: RawDecoder<T>,
  ): (resp: string) => T {
    return (resp) =>
      decode == null
        ? (undefined as T)
        : decode(JSON.parse(this.wit.decodeResult(fnName, resp)));
  }

  /** Build a proc-context `Inst` — emitted proc methods delegate here. */
  protected _proc<T>(
    fnName: string,
    args: Record<string, unknown>,
    decode?: RawDecoder<T>,
  ): Inst<T> {
    return this.session.call(
      this.address,
      fnName,
      this.callExpr(fnName, args),
      this.wrapDecoder(fnName, decode),
    );
  }

  /** Run a view-context query — emitted view methods delegate here. */
  protected async _view<T>(
    fnName: string,
    args: Record<string, unknown>,
    decode?: RawDecoder<T>,
  ): Promise<T> {
    const resp = await this.session.view(
      this.address,
      this.callExpr(fnName, args),
    );
    return this.wrapDecoder<T>(fnName, decode)(resp);
  }

  /**
   * Build an `Attachment` from a recognized attach/detach pair — the
   * emitted `attachment(...)` builder delegates here. Both halves share
   * one decoder: the convention requires the same `result` return type.
   */
  protected _attachment<T>(
    attachFn: string,
    attachArgs: Record<string, unknown>,
    detachFn: string,
    detachArgs: Record<string, unknown>,
    decode: RawDecoder<T>,
  ): Attachment<T> {
    return new Attachment(
      this.session,
      this._proc(attachFn, attachArgs, decode),
      this._proc(detachFn, detachArgs, decode),
    );
  }
}
