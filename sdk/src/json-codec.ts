/**
 * Transport that a generated `Contract` uses to dispatch encoded WAVE
 * expressions. Implementations decide the actual mechanism:
 *
 * - `simulate` for view-context calls (no chain mutation)
 * - `submit`   for proc-context calls (requires a transaction)
 *
 * The generated contract methods pick the right one based on the
 * function's context type, baked in at codegen time.
 */
export interface KontorTransport {
  simulate(wave: string): Promise<string>;
  submit(wave: string): Promise<string>;
}
