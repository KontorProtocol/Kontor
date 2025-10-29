import { useState, useEffect } from "react";
import "./App.css";
import {
  AddressPurpose,
  getProviders,
  request as satsConnectRequest,
  RpcErrorCode,
} from "sats-connect";

import * as bitcoin from "bitcoinjs-lib";

import "./App.css";

import * as ecc from "tiny-secp256k1";
import { ECPairFactory } from "ecpair";

// --- Constants ---
const SATS_PER_BTC = 100_000_000;
const PROVIDER_ID_XVERSE = "XverseProviders.BitcoinProvider";
const PROVIDER_ID_LEATHER = "LeatherProvider";
const PROVIDER_ID_UNISAT = "unisat";
const PROVIDER_ID_OKX = "okxwallet";
const PROVIDER_ID_PHANTOM = "phantom";
const PROVIDER_ID_HORIZON = "HorizonWalletProvider";
const ADDRESS_TYPE_P2TR = "p2tr";

const electrsUrl = import.meta.env.VITE_ELECTRS_URL;
const kontorUrl = import.meta.env.VITE_KONTOR_URL;

// --- Types ---
interface UnisatProvider {
  requestAccounts(): Promise<string[]>;
  getPublicKey(): Promise<string>;
  signPsbt(psbtHex: string, options?: any): Promise<string>;
}

interface OkxWallet {
  bitcoin: {
    connect(): Promise<{
      address: string;
      publicKey: string;
    }>;
    signPsbt(psbtHex: string, options?: any): Promise<string>;
  };
}

interface PhantomBtcAccount {
  address: string;
  addressType: "p2tr" | "p2wpkh" | "p2sh" | "p2pkh";
  publicKey: string;
  purpose: "payment" | "ordinals";
}

interface PhantomBitcoinProvider {
  requestAccounts(): Promise<PhantomBtcAccount[]>;
  signPSBT(
    psbt: Uint8Array,
    options: {
      inputsToSign: {
        address: string;
        signingIndexes: number[];
        sigHash?: number;
      }[];
    }
  ): Promise<string>;
}

interface PhantomWallet {
  bitcoin: PhantomBitcoinProvider;
}

declare global {
  interface Window {
    unisat?: UnisatProvider;
    okxwallet?: OkxWallet;
    phantom?: PhantomWallet;
  }
}

interface Provider {
  id: string;
  name: string;
  icon: string;
}

interface XverseAddressEntry {
  address: string;
  publicKey: string;
  purpose: AddressPurpose;
  addressType: string;
}

interface LeatherAddressEntry {
  address: string;
  publicKey: string;
  type: string;
  tweakedPublicKey: string;
}

interface ComposeAddressEntry {
  address: string;
  xOnlyPublicKey: string;
}

interface Utxo {
  txid: string;
  vout: number;
  value: number;
  status: {
    confirmed: boolean;
    block_height: number;
    block_hash: string;
    block_time: number;
  };
}

interface TransactionInput {
  previous_output: string;
  script_sig: string;
  sequence: number;
  witness: string[];
}

interface TransactionOutput {
  script_pubkey: string;
  value: number;
}

interface Transaction {
  version: number;
  lock_time: number;
  input: TransactionInput[];
  output: TransactionOutput[];
}

interface TapLeafScript {
  leafVersion: number;
  script: string;
  controlBlock: string;
}

interface ComposeResult {
  commit_transaction: Transaction;
  commit_transaction_hex: string;
  reveal_transaction: Transaction;
  reveal_transaction_hex: string;
  commit_psbt_hex: string;
  reveal_psbt_hex: string;
  tap_script: string;
  tap_leaf_script: TapLeafScript;
  chained_tap_script: string | null;
}

interface TestMempoolAcceptResult {
  txid: string;
  wtxid: string;
  allowed: boolean;
  reject_reason: string | null;
  vsize: number | null;
  fee: number | null;
}

interface TestMempoolAcceptResultWrapper {
  result: TestMempoolAcceptResult[];
}

// --- Helper Functions ---
const convertKebabToSnake = (obj: Record<string, any>): Record<string, any> => {
  return Object.entries(obj).reduce((acc, [key, value]) => {
    const snakeKey = key.replace(/-([a-z])/g, (_, letter) => `_${letter}`);
    acc[snakeKey] = value;
    return acc;
  }, {} as Record<string, any>);
};

async function fetchUtxos(address: string): Promise<Utxo[]> {
  const response = await fetch(`${electrsUrl}/address/${address}/utxo`);
  if (!response.ok) {
    throw new Error("Failed to fetch UTXOs");
  }
  return response.json();
}

async function composeCommitReveal(
  address: ComposeAddressEntry,
  utxos: Utxo[],
  inputData: string
): Promise<ComposeResult> {
  const fundingUtxoIds = utxos
    .map((utxo) => `${utxo.txid}:${utxo.vout}`)
    .join(",");

  // Serialize script data as bytes (Vec<u8> in backend JSON)
  const scriptBytes = Array.from(new TextEncoder().encode(inputData || ""));

  const body = {
    instructions: [
      {
        address: address.address,
        x_only_public_key: address.xOnlyPublicKey,
        funding_utxo_ids: fundingUtxoIds,
        script_data: scriptBytes,
      },
    ],
    sat_per_vbyte: 2,
  };

  const response = await fetch(`${kontorUrl}/api/compose`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data?.error || "Failed to compose transactions");
  }

  const r = data.result;
  const first = r?.per_participant?.[0];
  if (!first || !first.commit) {
    throw new Error("Compose response missing participant tap script data");
  }

  return {
    commit_transaction: r.commit_transaction,
    commit_transaction_hex: r.commit_transaction_hex,
    reveal_transaction: r.reveal_transaction,
    reveal_transaction_hex: r.reveal_transaction_hex,
    commit_psbt_hex: r.commit_psbt_hex,
    reveal_psbt_hex: r.reveal_psbt_hex,
    tap_script: first.commit.tap_script,
    tap_leaf_script: first.commit.tap_leaf_script,
    chained_tap_script: first.chained ? first.chained.tap_script : null,
  } as ComposeResult;
}

async function broadcastTestMempoolAccept(
  signedTx: string
): Promise<TestMempoolAcceptResult[]> {
  const response = await fetch(
    `${kontorUrl}/api/test_mempool_accept?txs=${signedTx}`
  );
  const rawData = await response.json();
  const convertedData: TestMempoolAcceptResultWrapper = {
    result: rawData.result.map((item: any) => convertKebabToSnake(item)),
  };
  return convertedData.result;
}

async function signPsbtWithXverse(
  psbtHex: string,
  sourceAddress: string,
  provider: string,
  scriptLeafData?: TapLeafScript
): Promise<string> {
  const psbt = bitcoin.Psbt.fromHex(psbtHex);

  if (scriptLeafData) {
    psbt.updateInput(0, {
      tapLeafScript: [
        {
          leafVersion: scriptLeafData.leafVersion,
          script: Buffer.from(scriptLeafData.script, "hex"),
          controlBlock: Buffer.from(scriptLeafData.controlBlock, "hex"),
        },
      ],
    });
  }

  const res = await satsConnectRequest(
    "signPsbt",
    {
      psbt: psbt.toBase64(),
      broadcast: false,
      signInputs: {
        [sourceAddress]: Array.from(
          { length: psbt.txInputs.length },
          (_, i) => i
        ),
      },
    },
    provider
  );

  if (res.status === "error") {
    throw new Error(`Signing failed: ${res.error || "Unknown error"}`);
  }

  const signedPsbt = bitcoin.Psbt.fromBase64(res.result.psbt);

  console.log("Input 0 data:", signedPsbt.data.inputs[0]);
  console.log("tapScriptSig:", signedPsbt.data.inputs[0].tapScriptSig);
  console.log("tapKeySig:", signedPsbt.data.inputs[0].tapKeySig);
  console.log(
    "Pre-existing finalScriptWitness length:",
    signedPsbt.data.inputs[0].finalScriptWitness?.length
  );

  // FORCE script-path spend by overriding the pre-finalized witness
  if (scriptLeafData) {
    const input = signedPsbt.data.inputs[0];

    if (!input.tapScriptSig || input.tapScriptSig.length === 0) {
      throw new Error("No taproot script signature found");
    }

    // Build witness stack for script-path: [signature, script, control_block]
    const witness: Buffer[] = [
      input.tapScriptSig[0].signature,
      Buffer.from(scriptLeafData.script, "hex"),
      Buffer.from(scriptLeafData.controlBlock, "hex"),
    ];

    console.log("Overriding with script-path witness:");
    console.log("  Signature:", witness[0].toString("hex"));
    console.log("  Script:", witness[1].toString("hex"));
    console.log("  Control Block:", witness[2].toString("hex"));

    // OVERRIDE the finalScriptWitness
    signedPsbt.data.inputs[0].finalScriptWitness = encodeWitness(witness);

    // Clear the partial signatures to prevent conflicts
    delete signedPsbt.data.inputs[0].tapScriptSig;
    delete signedPsbt.data.inputs[0].tapKeySig;
    delete signedPsbt.data.inputs[0].tapLeafScript;

    console.log(
      "New finalScriptWitness length:",
      signedPsbt.data.inputs[0].finalScriptWitness.length
    );
  } else {
    signedPsbt.finalizeAllInputs();
  }

  const tx = signedPsbt.extractTransaction();

  console.log("Final TX witness length:", tx.ins[0].witness.length);
  console.log(
    "Final TX witness items:",
    tx.ins[0].witness.map((w) => w.toString("hex"))
  );

  return tx.toHex();
}

// Helper to encode witness stack
function encodeWitness(witness: Buffer[]): Buffer {
  const buffers: Buffer[] = [];

  // Encode witness item count
  buffers.push(Buffer.from([witness.length]));

  // Encode each witness item with its length prefix
  witness.forEach((item) => {
    if (item.length < 253) {
      buffers.push(Buffer.from([item.length]));
    } else if (item.length <= 0xffff) {
      const buf = Buffer.allocUnsafe(3);
      buf.writeUInt8(253, 0);
      buf.writeUInt16LE(item.length, 1);
      buffers.push(buf);
    } else {
      throw new Error("Witness item too large");
    }
    buffers.push(item);
  });

  return Buffer.concat(buffers);
}

async function signPsbtWithLeather(
  psbtHex: string,
  sourceAddress: string,
  provider: string,
  scriptLeafData?: TapLeafScript
): Promise<string> {
  const psbt = bitcoin.Psbt.fromHex(psbtHex);

  if (scriptLeafData) {
    psbt.updateInput(0, {
      tapLeafScript: [
        {
          leafVersion: scriptLeafData.leafVersion,
          script: Buffer.from(scriptLeafData.script, "hex"),
          controlBlock: Buffer.from(scriptLeafData.controlBlock, "hex"),
        },
      ],
    });
  }

  const res = await satsConnectRequest(
    "signPsbt",
    {
      hex: psbt.toHex(),
      broadcast: false,
      signInputs: {
        [sourceAddress]: Array.from(
          { length: psbt.txInputs.length },
          (_, i) => i
        ),
      },
    } as any,
    provider
  );

  if (res.status === "error") {
    throw new Error(`Signing failed: ${res.error?.message || "Unknown error"}`);
  }

  const signedPsbt = bitcoin.Psbt.fromHex((res.result as any).hex);

  signedPsbt.finalizeAllInputs();
  const tx = signedPsbt.extractTransaction();
  return tx.toHex();
}

async function signPsbtWithOKX(
  psbtHex: string,
  scriptLeafData?: TapLeafScript
): Promise<string> {
  if (!window.okxwallet) {
    throw new Error("OKX Wallet not available");
  }

  const psbt = bitcoin.Psbt.fromHex(psbtHex);

  if (scriptLeafData) {
    psbt.updateInput(0, {
      tapLeafScript: [
        {
          leafVersion: scriptLeafData.leafVersion,
          script: Buffer.from(scriptLeafData.script, "hex"),
          controlBlock: Buffer.from(scriptLeafData.controlBlock, "hex"),
        },
      ],
    });
  }

  const options: any = {};

  // For script spend, disable tweak signer to use original private key
  if (scriptLeafData) {
    options.disableTweakSigner = true;
  }

  try {
    const signedPsbtHex = await window.okxwallet.bitcoin.signPsbt(
      psbt.toHex(),
      options
    );

    const signedPsbt = bitcoin.Psbt.fromHex(signedPsbtHex);

    // Manually create witness for all inputs
    for (let i = 0; i < signedPsbt.inputCount; i++) {
      const input = signedPsbt.data.inputs[i];

      if (input.tapKeySig && !scriptLeafData) {
        // Key spend: create witness with just the signature
        signedPsbt.updateInput(i, {
          finalScriptWitness: Buffer.concat([
            Buffer.from([input.tapKeySig.length]),
            input.tapKeySig,
          ]),
        });
      } else if (input.tapScriptSig && scriptLeafData) {
        // Script spend: create witness with signature + script + control block
        const scriptSig = input.tapScriptSig[0];
        signedPsbt.updateInput(i, {
          finalScriptWitness: Buffer.concat([
            Buffer.from([scriptSig.signature.length]),
            scriptSig.signature,
            Buffer.from([Buffer.from(scriptLeafData.script, "hex").length]),
            Buffer.from(scriptLeafData.script, "hex"),
            Buffer.from([
              Buffer.from(scriptLeafData.controlBlock, "hex").length,
            ]),
            Buffer.from(scriptLeafData.controlBlock, "hex"),
          ]),
        });
      }
    }

    const tx = signedPsbt.extractTransaction();
    return tx.toHex();
  } catch (err) {
    throw new Error(`OKX signing failed: ${err}`);
  }
}

async function signPsbtWithPhantom(
  psbtHex: string,
  sourceAddress: string,
  scriptLeafData?: TapLeafScript
): Promise<string> {
  if (!window.phantom?.bitcoin) {
    throw new Error("Phantom Wallet not available");
  }

  const psbt = bitcoin.Psbt.fromHex(psbtHex);

  if (scriptLeafData) {
    psbt.updateInput(0, {
      tapLeafScript: [
        {
          leafVersion: scriptLeafData.leafVersion,
          script: Buffer.from(scriptLeafData.script, "hex"),
          controlBlock: Buffer.from(scriptLeafData.controlBlock, "hex"),
        },
      ],
    });
  }

  // Sign all inputs that belong to the source address
  const inputsToSign = [
    {
      address: sourceAddress,
      signingIndexes: Array.from({ length: psbt.inputCount }, (_, i) => i),
      ...(scriptLeafData && { sigHash: 0x00 }),
    },
  ];

  try {
    const psbtBytes = new Uint8Array(Buffer.from(psbt.toHex(), "hex"));

    const signedPsbtBytes = await window.phantom.bitcoin.signPSBT(psbtBytes, {
      inputsToSign,
    });

    const signedPsbtHex = Buffer.from(signedPsbtBytes).toString("hex");

    const signedPsbt = bitcoin.Psbt.fromHex(signedPsbtHex);

    signedPsbt.finalizeAllInputs();
    const tx = signedPsbt.extractTransaction();
    return tx.toHex();
  } catch (err) {
    throw new Error(`Phantom signing failed: ${err}`);
  }
}

async function signPsbt(
  psbtHex: string,
  sourceAddress: string,
  provider: string,
  scriptLeafData?: TapLeafScript
): Promise<string> {
  switch (provider) {
    case PROVIDER_ID_LEATHER:
      return signPsbtWithLeather(
        psbtHex,
        sourceAddress,
        provider,
        scriptLeafData
      );
    case PROVIDER_ID_XVERSE:
      return signPsbtWithXverse(
        psbtHex,
        sourceAddress,
        provider,
        scriptLeafData
      );
    case PROVIDER_ID_OKX:
      return signPsbtWithOKX(psbtHex, scriptLeafData);
    case PROVIDER_ID_PHANTOM:
      return signPsbtWithPhantom(psbtHex, sourceAddress, scriptLeafData);
    default:
      throw new Error(`Unsupported provider: ${provider}`);
  }
}

// --- UI Components ---
const ErrorMessage: React.FC<{ error: string }> = ({ error }) => {
  if (!error) return null;
  return <p className="error">{error}</p>;
};

const ProviderSelector: React.FC<{
  provider: string;
  setProvider: (p: string) => void;
  availableProviders: Provider[];
}> = ({ provider, setProvider, availableProviders }) => {
  if (availableProviders.length === 0) return null;
  return (
    <div>
      <label htmlFor="provider-select">Choose a wallet provider: </label>
      <select
        id="provider-select"
        value={provider}
        onChange={(e) => setProvider(e.target.value)}
      >
        {availableProviders.map((p) => (
          <option key={p.id} value={p.id}>
            {p.name}
          </option>
        ))}
      </select>
    </div>
  );
};

const AddressInfo: React.FC<{
  address: ComposeAddressEntry;
  utxos: Utxo[];
}> = ({ address, utxos }) => (
  <div className="addresses">
    <h2>Your Taproot Address:</h2>
    <ul>
      <li>{address.address}</li>
    </ul>
    {utxos.length > 0 && (
      <div className="utxos">
        <h3>UTXOs:</h3>
        <ul>
          {utxos.map((utxo, index) => (
            <li key={index}>
              <strong>TXID:</strong> {utxo.txid}
              <br />
              <strong>Vout:</strong> {utxo.vout}
              <br />
              <strong>Value:</strong> {utxo.value / SATS_PER_BTC} BTC
              <br />
              <strong>Status:</strong>{" "}
              {utxo.status.confirmed ? "Confirmed" : "Unconfirmed"}
            </li>
          ))}
        </ul>
      </div>
    )}
  </div>
);

// --- Script decoding helpers ---
const getOpcodeName = (op: number): string => {
  const entry = Object.entries(bitcoin.opcodes).find(
    ([, value]) => value === op
  );
  return entry ? entry[0] : `OP_${op}`;
};

const isPrintableAscii = (buf: Uint8Array): boolean =>
  Array.from(buf).every((b) => b >= 32 && b <= 126);

const toAsciiOrHex = (buf: Uint8Array): string =>
  isPrintableAscii(buf)
    ? `"${Buffer.from(buf).toString("utf8")}` + `"`
    : Buffer.from(buf).toString("hex");

const decompileTapScriptToLines = (scriptBuffer: Buffer): string[] => {
  try {
    const chunks = bitcoin.script.decompile(scriptBuffer);
    if (!chunks) return ["<unable to decompile script>"];
    return chunks.map((chunk) => {
      if (Buffer.isBuffer(chunk)) {
        return `PUSH(${chunk.length}): ${toAsciiOrHex(chunk)}`;
      }
      return getOpcodeName(chunk as number);
    });
  } catch (_) {
    return ["<error decoding script>"];
  }
};

const TransactionDetails: React.FC<{ tx: Transaction; title: string }> = ({
  tx,
  title,
}) => (
  <>
    <h3>{title}:</h3>
    <div className="transaction-details">
      <p>
        <strong>Version:</strong> {tx.version}
      </p>
      <p>
        <strong>Lock Time:</strong> {tx.lock_time}
      </p>
      <h4>Inputs:</h4>
      <ul>
        {tx.input.map((input, index) => (
          <li key={index}>
            <strong>Previous Output:</strong> {input.previous_output}
            <br />
            <strong>Sequence:</strong> {input.sequence}
          </li>
        ))}
      </ul>
      <h4>Outputs:</h4>
      <ul>
        {tx.output.map((output, index) => (
          <li key={index}>
            <strong>Script Pubkey:</strong> {output.script_pubkey}
            <br />
            <strong>Value:</strong> {output.value / SATS_PER_BTC} BTC
          </li>
        ))}
      </ul>
    </div>
  </>
);

const ComposeResultDisplay: React.FC<{ composeResult: ComposeResult }> = ({
  composeResult,
}) => (
  <div className="transactions">
    <TransactionDetails
      tx={composeResult.commit_transaction}
      title="Commit Transaction"
    />
    <TransactionDetails
      tx={composeResult.reveal_transaction}
      title="Reveal Transaction"
    />
    <h3>Tap Script:</h3>
    <p className="tap-script">{composeResult.tap_script}</p>
  </div>
);

const Composer: React.FC<{
  inputData: string;
  setInputData: (d: string) => void;
  onCompose: () => void;
  disabled?: boolean;
  disabledMessage?: string;
}> = ({ inputData, setInputData, onCompose, disabled, disabledMessage }) => (
  <div className="compose-section">
    <div className="input-container">
      <input
        type="text"
        value={inputData}
        onChange={(e) => setInputData(e.target.value)}
        placeholder="Enter data to encode"
        className="data-input"
        style={{
          width: "100%",
          padding: "12px",
          marginBottom: "16px",
          fontSize: "16px",
          borderRadius: "4px",
          border: "1px solid #ccc",
        }}
      />
    </div>
    {disabled && disabledMessage && <p className="error">{disabledMessage}</p>}
    <button onClick={onCompose} disabled={disabled}>
      Compose Commit/Reveal Transactions
    </button>
  </div>
);

const Signer: React.FC<{
  signedCommitTx: string;
  signedRevealTx: string;
  onSign: () => void;
  onBroadcast: () => void;
}> = ({ signedCommitTx, signedRevealTx, onSign, onBroadcast }) => {
  // Only attempt to decode after both transactions are signed
  let decodedLines: string[] = [];
  try {
    if (signedCommitTx && signedRevealTx) {
      const revealTx = bitcoin.Transaction.fromHex(signedRevealTx);
      const witness = revealTx.ins?.[0]?.witness ?? [];
      console.log("Witness length:", witness.length);
      if (witness.length >= 2) {
        const scriptBuffer = witness[1];
        decodedLines = decompileTapScriptToLines(scriptBuffer as Buffer);
      }
    }
  } catch (e) {
    console.error("Signer decode error:", e);
  }

  return (
    <div className="sign-transaction">
      <button onClick={onSign}>Sign Transactions</button>
      {signedCommitTx && signedRevealTx && (
        <>
          <div className="signed-transaction">
            <h3>Signed Commit Transaction:</h3>
            <p className="tx-hex">{signedCommitTx}</p>
          </div>
          <div className="signed-transaction">
            <h3>Signed Reveal Transaction:</h3>
            <p className="tx-hex">{signedRevealTx}</p>
          </div>
          {decodedLines.length > 0 && (
            <div className="transaction-details">
              <h4>Decoded Tap Script (from witness[len-2]):</h4>
              <ul>
                {decodedLines.map((line, i) => (
                  <li key={i}>{line}</li>
                ))}
              </ul>
            </div>
          )}
          <button onClick={onBroadcast}>Test Broadcast Transactions</button>
          <p>Note: Transaction will not be broadcasted to the network.</p>
        </>
      )}
    </div>
  );
};

const BroadcastResultDisplay: React.FC<{
  broadcastedTx: TestMempoolAcceptResult[];
}> = ({ broadcastedTx }) => {
  if (broadcastedTx.length === 0) return null;
  return (
    <div className="broadcasted-transaction">
      <h3>Broadcasted Transaction Result:</h3>
      <ul>
        {broadcastedTx.map((tx, index) => (
          <li key={index}>
            <strong>TXID:</strong> {tx.txid}
            <p>Allowed: {tx.allowed ? "Yes" : "No"}</p>
            {tx.reject_reason && <p>Reject Reason: {tx.reject_reason}</p>}
            {tx.vsize && <p>Vsize: {tx.vsize}</p>}
            {tx.fee && <p>Fee: {tx.fee}</p>}
          </li>
        ))}
      </ul>
    </div>
  );
};

// --- Main Wallet Component ---
function WalletComponent() {
  const [address, setAddress] = useState<ComposeAddressEntry | undefined>();
  const [utxos, setUtxos] = useState<Utxo[]>([]);
  const [composeResult, setComposeResult] = useState<
    ComposeResult | undefined
  >();
  const [error, setError] = useState<string>("");
  const [signedCommitTx, setSignedCommitTx] = useState<string>("");
  const [signedRevealTx, setSignedRevealTx] = useState<string>("");
  const [broadcastedTx, setBroadcastedTx] = useState<TestMempoolAcceptResult[]>(
    []
  );
  const [inputData, setInputData] = useState<string>("");
  const [provider, setProvider] = useState<string>("");
  const [availableProviders, setAvailableProviders] = useState<Provider[]>([]);

  const handleProviderChange = (newProvider: string) => {
    setProvider(newProvider);
    setAddress(undefined);
    setUtxos([]);
    setInputData("");
    setSignedCommitTx("");
    setSignedRevealTx("");
    setBroadcastedTx([]);
    setComposeResult(undefined);
    setError("");
  };

  useEffect(() => {
    const providers = getProviders();
    if (window.unisat && !providers.find((p) => p.id === PROVIDER_ID_UNISAT)) {
      providers.push({ id: PROVIDER_ID_UNISAT, name: "UniSat", icon: "" });
    }
    if (window.okxwallet && !providers.find((p) => p.id === PROVIDER_ID_OKX)) {
      providers.push({ id: PROVIDER_ID_OKX, name: "OKX Wallet", icon: "" });
    }
    if (
      window.phantom?.bitcoin &&
      !providers.find((p) => p.id === PROVIDER_ID_PHANTOM)
    ) {
      providers.push({
        id: PROVIDER_ID_PHANTOM,
        name: "Phantom",
        icon: "",
      });
    }

    if (providers?.length > 0) {
      setAvailableProviders(providers);
      if (!provider) {
        setProvider(providers[0].id);
      }
    }
  }, [provider]);

  const handleGetAddresses = async () => {
    setError("");
    try {
      switch (provider) {
        case PROVIDER_ID_UNISAT:
          if (window.unisat) {
            const accounts = await window.unisat.requestAccounts();
            const publicKey = await window.unisat.getPublicKey();
            if (accounts.length > 0) {
              const paymentAddress: ComposeAddressEntry = {
                address: accounts[0],
                xOnlyPublicKey: publicKey,
              };
              setAddress(paymentAddress);
              handleFetchUtxos(paymentAddress.address);
            }
          }
          break;
        case PROVIDER_ID_OKX:
          if (window.okxwallet) {
            const { address, publicKey } =
              await window.okxwallet.bitcoin.connect();

            const paymentAddress: ComposeAddressEntry = {
              address,
              xOnlyPublicKey: publicKey,
            };
            setAddress(paymentAddress);
            handleFetchUtxos(paymentAddress.address);
          }
          break;
        case PROVIDER_ID_PHANTOM:
          if (window.phantom?.bitcoin) {
            const accounts = await window.phantom.bitcoin.requestAccounts();
            const paymentAccount = accounts.find(
              (acc) => acc.addressType === "p2tr" && acc.purpose === "payment"
            );

            if (paymentAccount) {
              const paymentAddress: ComposeAddressEntry = {
                address: paymentAccount.address,
                xOnlyPublicKey: paymentAccount.publicKey.slice(-64),
              };
              setAddress(paymentAddress);
              handleFetchUtxos(paymentAddress.address);
            } else {
              setError(
                "Could not find a P2TR payment address in Phantom wallet."
              );
            }
          }
          break;
        case PROVIDER_ID_XVERSE: {
          const getAddresses = () =>
            satsConnectRequest(
              "getAddresses",
              {
                purposes: [
                  AddressPurpose.Payment,
                  AddressPurpose.Ordinals,
                  AddressPurpose.Stacks,
                ],
              },
              provider
            );
          let response = await getAddresses();

          if (response.status === "error") {
            if (response.error.code === RpcErrorCode.ACCESS_DENIED) {
              await satsConnectRequest(
                "wallet_requestPermissions",
                undefined,
                provider
              );
              response = await getAddresses();
            } else {
              throw new Error(
                response.error.message || "Failed to get addresses."
              );
            }
          }

          if (response.status === "success") {
            const paymentAddress = (
              response.result.addresses as XverseAddressEntry[]
            ).find(
              (addr) =>
                (addr as XverseAddressEntry).addressType === ADDRESS_TYPE_P2TR
            );

            if (paymentAddress) {
              const composeAddress: ComposeAddressEntry = {
                address: paymentAddress.address,
                xOnlyPublicKey: paymentAddress.publicKey,
              };
              setAddress(composeAddress);
              handleFetchUtxos(composeAddress.address);
            } else {
              setError("Could not find a P2TR (Taproot) payment address.");
            }
          }
          break;
        }
        case PROVIDER_ID_LEATHER: {
          const getAddresses = () =>
            satsConnectRequest(
              "getAddresses",
              {
                purposes: [
                  AddressPurpose.Payment,
                  AddressPurpose.Ordinals,
                  AddressPurpose.Stacks,
                ],
              },
              provider
            );
          let response = await getAddresses();

          if (response.status === "error") {
            throw new Error(
              response.error.message || "Failed to get addresses."
            );
          }

          if (response.status === "success") {
            const paymentAddress = (
              response.result.addresses as unknown as LeatherAddressEntry[]
            ).find(
              (addr) => (addr as LeatherAddressEntry).type === ADDRESS_TYPE_P2TR
            );

            if (paymentAddress) {
              const composeAddress: ComposeAddressEntry = {
                address: paymentAddress.address,
                xOnlyPublicKey: (paymentAddress as LeatherAddressEntry)
                  .tweakedPublicKey,
              };
              setAddress(composeAddress);
              handleFetchUtxos(composeAddress.address);
            } else {
              setError("Could not find a P2TR (Taproot) payment address.");
            }
          }
          break;
        }
      }
    } catch (err) {
      const providerName =
        availableProviders.find((p) => p.id === provider)?.name || provider;
      setError(`Error with ${providerName}: ${err}`);
    }
  };

  const handleFetchUtxos = async (addr: string) => {
    try {
      const utxoData = await fetchUtxos(addr);
      setUtxos(utxoData);
    } catch (err) {
      setError(`An error occurred while fetching UTXOs: ${err}`);
    }
  };

  const handleCompose = async () => {
    if (!address || utxos.length === 0) return;
    setError("");
    try {
      const kontorData = await composeCommitReveal(address, utxos, inputData);
      setComposeResult(kontorData);
    } catch (err) {
      setError(`An error occurred while composing: ${err}`);
    }
  };

  const handleSignTransaction = async () => {
    if (!address || !composeResult) return;
    setError("");
    try {
      bitcoin.initEccLib(ecc);
      ECPairFactory(ecc);

      const commitSignResult = await signPsbt(
        composeResult.commit_psbt_hex,
        address.address,
        provider
      );

      const revealSignResult = await signPsbt(
        composeResult.reveal_psbt_hex,
        address.address,
        provider,
        composeResult.tap_leaf_script
      );
      setSignedCommitTx(commitSignResult);
      setSignedRevealTx(revealSignResult);
    } catch (err) {
      console.log("ERROR:", err);
      setError(`An error occurred while signing: ${err}`);
    }
  };

  const handleBroadcastTransaction = async () => {
    if (!signedCommitTx || !signedRevealTx) return;
    setError("");
    try {
      const result = await broadcastTestMempoolAccept(
        [signedCommitTx, signedRevealTx].join(",")
      );
      setBroadcastedTx(result);
    } catch (err) {
      setError(`An error occurred while broadcasting: ${err}`);
    }
  };

  const isUnisat = provider === PROVIDER_ID_UNISAT;
  const unisatMessage =
    "Unisat does not provide the necessary x-only public key for composing a taproot transaction.";

  const isHorizon = provider === PROVIDER_ID_HORIZON;
  const horizonMessage = "Horizon does not yet support taproot :)";
  return (
    <div className="wallet-container">
      <h1>COMPOSE</h1>
      <ProviderSelector
        provider={provider}
        setProvider={handleProviderChange}
        availableProviders={availableProviders}
      />
      <button onClick={handleGetAddresses} disabled={isHorizon}>
        Get Wallet Addresses
      </button>

      {isHorizon && <p className="error">{horizonMessage}</p>}
      <ErrorMessage error={error} />

      {address && <AddressInfo address={address} utxos={utxos} />}

      {composeResult && <ComposeResultDisplay composeResult={composeResult} />}

      {!composeResult && address && utxos.length > 0 && (
        <Composer
          inputData={inputData}
          setInputData={setInputData}
          onCompose={handleCompose}
          disabled={isUnisat}
          disabledMessage={isUnisat ? unisatMessage : undefined}
        />
      )}

      {composeResult && (
        <Signer
          signedCommitTx={signedCommitTx}
          signedRevealTx={signedRevealTx}
          onSign={handleSignTransaction}
          onBroadcast={handleBroadcastTransaction}
        />
      )}

      <BroadcastResultDisplay broadcastedTx={broadcastedTx} />
    </div>
  );
}

function App() {
  return <WalletComponent />;
}

export default App;
