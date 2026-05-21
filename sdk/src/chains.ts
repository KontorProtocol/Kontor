/**
 * Chain configs — static data for each Kontor network the SDK knows
 * about. A `Chain` carries everything `KontorSession` / `HttpTransport`
 * need to talk to one network: endpoint URLs, Bitcoin network params
 * for address encoding, and known native contract addresses.
 *
 * Today: just `signet`. Add `mainnet` / `regtest` here when they're
 * available — single file rather than the old one-per-network layout,
 * since the configs are tiny.
 */

import { ContractAddress } from "./canonical/ContractAddress.js";

export interface ChainUrls {
  /** Indexer HTTP API base, e.g. `https://signet.kontor.network:35001/api`. */
  http: string;
  /** Indexer WebSocket endpoint for live updates. */
  webSocket?: string;
  /** Bitcoin Core RPC endpoint, used for UTXO fetching + tx broadcast. */
  bitcoinRpc: string;
}

export interface BlockExplorer {
  name: string;
  url: string;
  apiUrl?: string;
}

/**
 * Bitcoin network parameters consumed by address-encoding libraries
 * (`@scure/btc-signer`). Values are the standard ones for each Bitcoin
 * network — see BIP-173 and the Bitcoin Core source.
 */
export interface BitcoinNetwork {
  /** bech32 HRP prefix: "bc" mainnet / "tb" testnet+signet / "bcrt" regtest. */
  bech32: string;
  pubKeyHash: number;
  scriptHash: number;
  wif: number;
}

export interface Chain {
  name: string;
  nativeCurrency: { name: string; symbol: string; decimals: number };
  /** Median block time in milliseconds (used for polling cadence). */
  blockTime: number;
  urls: ChainUrls;
  blockExplorer?: BlockExplorer;
  /** Pre-known native contract addresses on this chain. */
  contracts?: {
    nativeToken?: { name: string; height: bigint; txIndex: bigint };
  };
  network: BitcoinNetwork;
}

export const signet: Chain = {
  name: "signet",
  nativeCurrency: { name: "Kontor", symbol: "KOR", decimals: 18 },
  blockTime: 10 * 60 * 1_000,
  urls: {
    http: "https://signet.kontor.network:35001/api",
    webSocket: "wss://signet.kontor.network:35001/ws",
    bitcoinRpc: "https://signet.kontor.network:38332",
  },
  blockExplorer: {
    name: "mempool.space",
    url: "https://mempool.space/signet",
    apiUrl: "https://mempool.space/signet/api",
  },
  contracts: {
    nativeToken: { name: "token", height: 0n, txIndex: 0n },
  },
  network: {
    bech32: "tb",
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef,
  },
};

/** Convenience: turn a chain's `contracts.nativeToken` into a ContractAddress. */
export function nativeTokenAddress(chain: Chain): ContractAddress {
  const nt = chain.contracts?.nativeToken;
  if (nt == null) {
    throw new Error(`chain '${chain.name}' has no nativeToken configured`);
  }
  return new ContractAddress(nt.name, nt.height, nt.txIndex);
}
