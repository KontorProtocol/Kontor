## UI
The Kontor indexer must be running first.

### Run

```bash
cd ui
cargo run
```

UI runs at localhost:3000

### Development

Add environment variables to `.envrc`:
```bash
export VITE_ELECTRS_URL="https://api.unspendablelabs.com:3000"
export VITE_KONTOR_URL="https://localhost:9333"
```

```bash
cd ui/frontend
npm install
npm run dev
```

Dev server runs at localhost:5173

To build the frontend for release, before merging, in the frontend dir
```bash
cd ui/frontend
npm run build
```
