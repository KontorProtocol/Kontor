import { useState } from 'react'
import { request } from '@stacks/connect'
import './App.css'
import type { AddressEntry, GetAddressesResult } from '@stacks/connect/dist/types/methods'

interface ExtendedAddressEntry extends AddressEntry {
  purpose: string
  addressType: string
}

function WalletComponent() {
  const [address, setAddress] = useState<ExtendedAddressEntry | undefined>()
  const [error, setError] = useState<string>('')

  const handleGetAddresses = async () => {
    try {
      const response: GetAddressesResult = await request('getAddresses')
      console.log(response)

      // Find the address with purpose "payment"
      const paymentAddress = (response.addresses as ExtendedAddressEntry[]).find(
        addr => addr.addressType === 'p2tr'
      )
      setAddress(paymentAddress)
    } catch (err) {
      setError('Failed to get addresses')
      console.error(err)
    }
  }

  return (
    <div className="wallet-container">
      <h1>Stacks Wallet Address Fetcher</h1>
      <button onClick={handleGetAddresses}>Get Wallet Addresses</button>
      {address && (
        <div className="addresses">
          <h2>Your Payment Address:</h2>
          <ul>
            <li>
              <strong>{address.purpose}:</strong> {address.address}
            </li>
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
