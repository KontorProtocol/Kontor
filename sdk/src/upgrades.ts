import { TransportError } from "./errors.js";

/** Heights, nonces and voting powers remain exact decimal strings on the wire. */
export interface UpgradeState {
  chain_id: string;
  era_id: string;
  protocol_id: string;
  control_head: string;
  nonce: string;
  reference_height: string;
  reference_decision: string;
  bitcoin_height: string;
  bitcoin_hash: string;
  minimum_reference_height: string;
  pending: {
    plan_id: string;
    target_protocol: string;
    activation_height: string;
    consumed: boolean;
    manifest_hex: string;
  } | null;
  inclusion_height: string;
  committee: { key: string; generation: string; power: string }[];
  state_hex: string;
}

export interface PrepareUpgrade {
  expires_at: string;
  operation:
    | { kind: "schedule"; manifest_hex: string; activation_height: string }
    | { kind: "postpone"; activation_height: string }
    | { kind: "cancel" };
}

export interface PreparedUpgrade {
  action_id: string;
  action_hex: string;
}

export interface QueuedUpgrade {
  action_id: string;
  control_id: string;
  status: "queued";
}

export interface UpgradeClientOptions {
  /** Indexer API base URL, including `/api` where applicable. */
  url: string;
  fetch?: typeof fetch;
  headers?: Record<string, string>;
}

/** Operator control has separate validator approvals from Bitcoin wallet signing. */
export class UpgradeClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly options: UpgradeClientOptions) {
    this.baseUrl = options.url.replace(/\/+$/, "");
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  state(signal?: AbortSignal): Promise<UpgradeState> {
    return this.request("GET", "", undefined, signal);
  }

  /** Returns unsigned canonical bytes. Inspect and approve them explicitly. */
  prepare(
    request: PrepareUpgrade,
    signal?: AbortSignal,
  ): Promise<PreparedUpgrade> {
    return this.request("POST", "/prepare", request, signal);
  }

  /** Local queue acknowledgement only. Does not imply consensus acceptance. */
  submit(envelopeHex: string, signal?: AbortSignal): Promise<QueuedUpgrade> {
    return this.request("POST", "", { envelope_hex: envelopeHex }, signal);
  }

  private async request<T>(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
    signal?: AbortSignal,
  ): Promise<T> {
    const url = `${this.baseUrl}/protocol/upgrades${path}`;
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method,
        headers: {
          ...this.options.headers,
          "content-type": "application/json",
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal,
      });
    } catch (cause) {
      throw new TransportError(`${method} ${url} failed`, {
        cause: cause instanceof Error ? cause : undefined,
      });
    }
    let value: unknown;
    try {
      value = await response.json();
    } catch (cause) {
      throw new TransportError(
        `${method} ${url} returned invalid JSON (HTTP ${response.status})`,
        {
          cause: cause instanceof Error ? cause : undefined,
        },
      );
    }
    if (!response.ok) {
      const detail =
        value !== null &&
        typeof value === "object" &&
        "error" in value &&
        typeof value.error === "string"
          ? value.error
          : undefined;
      throw new TransportError(
        `${method} ${url} returned HTTP ${response.status}`,
        { details: detail },
      );
    }
    if (
      value === null ||
      typeof value !== "object" ||
      !("result" in value) ||
      value.result === null
    ) {
      throw new TransportError(`${method} ${url} returned no result`);
    }
    return value.result as T;
  }
}
