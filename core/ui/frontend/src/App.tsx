import { useState } from 'react'
import './App.css'
import type { AddressEntry, GetAddressesResult } from '@stacks/connect/dist/types/methods'
import {
  request as satsConnectRequest,
} from "sats-connect";

import { request as connectRequest } from '@stacks/connect'

import * as bitcoin from 'bitcoinjs-lib'

import './App.css'

import * as ecc from 'tiny-secp256k1';
import { ECPairFactory } from 'ecpair';

interface ExtendedAddressEntry extends AddressEntry {
  purpose: string
  addressType: string
}

interface Utxo {
  txid: string
  vout: number
  value: number
  status: {
    confirmed: boolean
    block_height: number
    block_hash: string
    block_time: number
  }
}

interface TransactionInput {
  previous_output: string
  script_sig: string
  sequence: number
  witness: string[]
}

interface TransactionOutput {
  script_pubkey: string
  value: number
}

interface Transaction {
  version: number
  lock_time: number
  input: TransactionInput[]
  output: TransactionOutput[]
}

interface TapLeafScript {
  leafVersion: number
  script: string
  controlBlock: string
}

interface ComposeResult {
  commit_transaction: Transaction
  commit_transaction_hex: string
  reveal_transaction: Transaction
  reveal_transaction_hex: string
  commit_psbt_hex: string
  reveal_psbt_hex: string
  tap_script: string
  tap_leaf_script: TapLeafScript
  chained_tap_script: string | null
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
  result: TestMempoolAcceptResult[]
}

const convertKebabToSnake = (obj: Record<string, any>): Record<string, any> => {
  return Object.entries(obj).reduce((acc, [key, value]) => {
    const snakeKey = key.replace(/-([a-z])/g, (_, letter) => `_${letter}`);
    acc[snakeKey] = value;
    return acc;
  }, {} as Record<string, any>);
};



async function signPsbt(
  psbtHex: string,
  sourceAddress: string,
  scriptLeafData?: TapLeafScript
): Promise<string> {
  const psbt = bitcoin.Psbt.fromHex(psbtHex);

  if (scriptLeafData) {
    psbt.updateInput(
      0,
      {
        tapLeafScript: [{
          leafVersion: scriptLeafData.leafVersion,
          script: Buffer.from(scriptLeafData.script, 'hex'),
          controlBlock: Buffer.from(scriptLeafData.controlBlock, 'hex')
        }
        ]
      }
    )
  }

  const res = await satsConnectRequest('signPsbt', {
    psbt: psbt.toBase64(),
    broadcast: false,
    signInputs: { [sourceAddress]: Array.from({ length: psbt.txInputs.length }, (_, i) => i) },

  });

  if (res.status === 'error') {
    throw new Error(`Signing failed: ${res.error || 'Unknown error'}`);
  }

  const signedPsbt = bitcoin.Psbt.fromBase64(res.result.psbt);
  signedPsbt.finalizeAllInputs();
  const tx = signedPsbt.extractTransaction();

  return tx.toHex();
}


function WalletComponent() {
  const [address, setAddress] = useState<ExtendedAddressEntry | undefined>()
  const [utxos, setUtxos] = useState<Utxo[]>([])
  const [composeResult, setComposeResult] = useState<ComposeResult | undefined>()
  const [error, setError] = useState<string>('')
  const [signedTx, setSignedTx] = useState<string>('');
  const [broadcastedTx, setBroadcastedTx] = useState<TestMempoolAcceptResult[]>([])
  const [inputData, setInputData] = useState<string>('')


  const handleGetAddresses = async () => {
    try {
      const response: GetAddressesResult = await connectRequest('getAddresses')
      const paymentAddress = (response.addresses as ExtendedAddressEntry[]).find(
        addr => addr.addressType === 'p2tr'
      )
      setAddress(paymentAddress)

      if (paymentAddress) {
        const electrsUrl = import.meta.env.VITE_ELECTRS_URL
        const utxoResponse = await fetch(`${electrsUrl}/address/${paymentAddress.address}/utxo`)
        if (!utxoResponse.ok) {
          throw new Error('Failed to fetch UTXOs')
        }
        const utxoData = await utxoResponse.json()
        setUtxos(utxoData)
      }
    } catch (err) {
      setError('Failed to get addresses or UTXOs')
    }
  }

  const handleCompose = async (address: ExtendedAddressEntry, utxos: Utxo[]) => {
    if (utxos.length > 0) {
      const kontorUrl = import.meta.env.VITE_KONTOR_URL
      const base64EncodedData = btoa(inputData || '')
      const kontorResponse = await fetch(`${kontorUrl}/compose?address=${address.address}&x_only_public_key=${address.publicKey}&funding_utxo_ids=${utxos.map(utxo => utxo.txid + ':' + utxo.vout).join(',')}&sat_per_vbyte=2&script_data=${base64EncodedData}`)
      const kontorData = await kontorResponse.json()

      setComposeResult(kontorData.result)
    }
  }


  const handleSignTransaction = async () => {
    if (!address || !composeResult || utxos.length === 0) {
      setError('No address, transaction, or UTXOs to sign');
      return;
    }

    try {
      bitcoin.initEccLib(ecc);

      ECPairFactory(ecc);

      const commit_sign_result = await signPsbt(composeResult.commit_psbt_hex, address.address);
      const reveal_sign_result = await signPsbt(composeResult.reveal_psbt_hex, address.address, composeResult.tap_leaf_script);

      setSignedTx([commit_sign_result, reveal_sign_result].join(','));
    } catch (err) {
      setError('Failed to sign transaction');
    }
  };

  const handleBroadcastTransaction = async (signedTx: string) => {
    const kontorUrl = import.meta.env.VITE_KONTOR_URL
    const kontorResponse = await fetch(`${kontorUrl}/api/test_mempool_accept?txs=${signedTx}`)
    const rawData = await kontorResponse.json()

    const convertedData = {
      result: rawData.result.map((item: any) => convertKebabToSnake(item))
    } as TestMempoolAcceptResultWrapper
    setBroadcastedTx(convertedData.result)
  }

  return (
    <div className="wallet-container">
      <h1>COMPOSE</h1>
      <button onClick={handleGetAddresses}>Get Wallet Addresses</button>
      {address && (
        <div className="addresses">
          <h2>Your Taproot Address:</h2>
          <ul>
            <li>
              <strong>{address.purpose}:</strong> {address.address}
            </li>
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
                    <strong>Value:</strong> {utxo.value / 100000000} BTC
                    <br />
                    <strong>Status:</strong> {utxo.status.confirmed ? 'Confirmed' : 'Unconfirmed'}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {composeResult && (
            <div className="transactions">
              <h3>Commit Transaction:</h3>
              <div className="transaction-details">
                <p><strong>Version:</strong> {composeResult.commit_transaction.version}</p>
                <p><strong>Lock Time:</strong> {composeResult.commit_transaction.lock_time}</p>
                <h4>Inputs:</h4>
                <ul>
                  {composeResult.commit_transaction.input.map((input, index) => (
                    <li key={index}>
                      <strong>Previous Output:</strong> {input.previous_output}
                      <br />
                      <strong>Sequence:</strong> {input.sequence}
                    </li>
                  ))}
                </ul>
                <h4>Outputs:</h4>
                <ul>
                  {composeResult.commit_transaction.output.map((output, index) => (
                    <li key={index}>
                      <strong>Script Pubkey:</strong> {output.script_pubkey}
                      <br />
                      <strong>Value:</strong> {output.value / 100000000} BTC
                    </li>
                  ))}
                </ul>

              </div>

              <h3>Reveal Transaction:</h3>
              <div className="transaction-details">
                <p><strong>Version:</strong> {composeResult.reveal_transaction.version}</p>
                <p><strong>Lock Time:</strong> {composeResult.reveal_transaction.lock_time}</p>
                <h4>Inputs:</h4>
                <ul>
                  {composeResult.reveal_transaction.input.map((input, index) => (
                    <li key={index}>
                      <strong>Previous Output:</strong> {input.previous_output}
                      <br />
                      <strong>Sequence:</strong> {input.sequence}
                    </li>
                  ))}
                </ul>
                <h4>Outputs:</h4>
                <ul>
                  {composeResult.reveal_transaction.output.map((output, index) => (
                    <li key={index}>
                      <strong>Script Pubkey:</strong> {output.script_pubkey}
                      <br />
                      <strong>Value:</strong> {output.value / 100000000} BTC
                    </li>
                  ))}
                </ul>

              </div>

              <h3>Tap Script:</h3>
              <p className="tap-script">{composeResult.tap_script}</p>
            </div>
          )}
        </div>
      )}
      {
        !composeResult && address && utxos.length > 0 && (
          <div className="compose-section">
            <div className="input-container">
              <input
                type="text"
                value={inputData}
                onChange={(e) => setInputData(e.target.value)}
                placeholder="Enter data to encode"
                className="data-input"
                style={{
                  width: '100%',
                  padding: '12px',
                  marginBottom: '16px',
                  fontSize: '16px',
                  borderRadius: '4px',
                  border: '1px solid #ccc'
                }}
              />
            </div>
            <button onClick={() => handleCompose(address, utxos)}>Compose Commit/Reveal Transactions</button>
          </div>
        )
      }
      {composeResult && (
        <div className="sign-transaction">

          <button onClick={handleSignTransaction}>Sign Commit Transaction</button>

          {signedTx && (
            <>
              <div className="signed-transaction">
                <h3>Signed Transaction:</h3>
                <p className="tx-hex">{signedTx}</p>
              </div>

              <button onClick={() => handleBroadcastTransaction(signedTx)}>Broadcast Transaction</button>
            </>
          )}
        </div>
      )}
      {broadcastedTx.length > 0 && (
        <div className="broadcasted-transaction">
          <h3>Broadcasted Transaction:</h3>
          <ul>
            {broadcastedTx.map((tx, index) => (
              <li key={index}>
                <strong>TXID:</strong> {tx.txid}
                <p>Allowed: {tx.allowed ? 'Yes' : 'No'}</p>
                <p>Reject Reason: {tx.reject_reason}</p>
                <p>Vsize: {tx.vsize}</p>
                <p>Fee: {tx.fee}</p>
              </li>
            ))}
          </ul>
        </div>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  )
}

function App() {
  return <WalletComponent />
}

export default App


