/** @module Interface root:component/wit-api **/

export class Wit {
  constructor(text: string)
  encodeCall(fnName: string, argsJson: string): string;
  decodeResult(fnName: string, wave: string): string;
  parse(): string;
}
