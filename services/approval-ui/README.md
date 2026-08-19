# Approval UI

React + Vite approval console for the Hermes Policy Gateway. Built output is embedded into the Go gateway at `/ui`.

## Design intent

Utilitarian internal-system wireframe aesthetic — dense tables, gray panels, sharp borders, monospace IDs. Not a marketing or portfolio site.

## Development

With the gateway running on `:8080`:

```bash
npm install
npm run dev
```

Open http://localhost:5173/ui/ — API calls proxy to the gateway.

## Production build

```bash
npm run build
```

Output: `../policy-gateway/internal/ui/dist/` (embedded via `go:embed`).

Or from repo root: `make ui-build`
