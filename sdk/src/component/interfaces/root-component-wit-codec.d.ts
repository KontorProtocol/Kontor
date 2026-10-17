/** @module Interface root:component/wit-codec **/

export class Wit implements Disposable {
  constructor(text: string)
  encodeCall(fnName: string, argsJson: string): string;
  decodeResult(fnName: string, wave: string): string;
  parse(): string;
  [Symbol.dispose](): void;
}
