# Mandate Desk

![Mandate Desk card: owner approval for agent transfers](media/mandate-desk-card.png)

Mandate Desk is a project by Erik Rekola. The card uses the wordmark and visual style of turva.dev, his agent-readiness audit business.

Mandate Desk lets an owner set transfer limits, review an agent's request and approve its exact contents. The agent can prepare requests and execute an approved plan. Owner approval and revocation stay in the owner workspace.

This repository contains a working local MDT simulation and a separate offline preparation workspace for Ethereum Sepolia. The simulation uses a synthetic ledger. The Sepolia workspace builds unsigned transaction previews from fixtures. Its signer is unavailable by default. The repository contains no completed live transaction or hosted deployment.

The package version is 0.2.0-preview.1. The existing simulation MCP interface retains version 0.1.1. Earlier review verdicts apply to their original source snapshots, not automatically to this expanded code.

## Start the demo

Requirements are Windows, an existing PowerShell session and Node.js 24 or later. No dependency installation, API key, wallet or browser extension is required to run the application. Clone or download the repository, open PowerShell in its directory and run this one block:

```powershell
$ErrorActionPreference = 'Stop'
node .\tools\check-demo.mjs
if ($LASTEXITCODE -ne 0) { throw 'The package checks failed.' }
node .\tools\write-mcp-config.mjs
if ($LASTEXITCODE -ne 0) { throw 'MCP configuration could not be created.' }
& .\start-demo.ps1 -Port 4327 -Data '.local-demo'
```

Open [the owner workspace](http://127.0.0.1:4327/). The server binds only to this computer's loopback address. The launcher verifies the runtime, data path and server identity. It preserves occupied ports and existing application data. Generated state and MCP configuration stay in .local-demo inside the repository folder.

The [demo guide](DEMO.md) covers the complete sequence. The media folder includes an actual recorded canvas walkthrough of observed local API results. No microphone, camera or private desktop capture was used.

## Owner and agent workflow

The simulation starts with 1000 MDT, a limit of 60 MDT per transfer and a total limit of 100 MDT. The owner creates or revokes mandates. The agent prepares a request and runs preflight. The owner reviews its recipient, amount and plan hash before approval. Execution rechecks the current mandate and approval. Repeating an executed request with the same identity returns the existing receipt without another ledger change.

The example accepts 30 MDT, denies 80 MDT, accepts 50 MDT and denies 25 MDT. It then revokes the mandate and denies 1 MDT. These denials are enforced by local simulation policy. They have no blockchain transaction hash. Previous activity remains available when a new example starts.

The [Sepolia preparation workspace](http://127.0.0.1:4327/integration) displays the separate unsigned lifecycle. Its fixture recipient is the synthetic address 0x8888888888888888888888888888888888888888. Local preview approval does not authorize a chain write. Attempting execution reports SIGNING_ROUTE_UNAVAILABLE. Fixture balances, nonces and fee settings are not a current chain preflight.

## Architecture and trust boundary

The browser and simulation MCP server share the same domain checks and persistent store. HTTP writes require a local session token and matching origin. The application offers no remote authentication or Internet-facing deployment mode.

The integration modules validate complete unsigned envelopes for setAction, token approval, grant, execute and revoke. Validation binds chain, signer, target, nonce, value, calldata, fee ceilings, validity and the trusted preparation hash. That expectation is rebuilt from the fixture and the approval. A changed persisted preparation cannot become trusted merely by recomputing its own hash. The HTTP preparation caller classifies every non-200 response before reading its body. A payment challenge never triggers payment.

The recovery journal separates pending, signed, broadcast, uncertain, confirmed and semantically verified states. It preserves transaction identity across retries. An unresolved broadcast permits only the same signed bytes after recovery checks. A nonce conflict stops. Semantic postchecks inspect transaction identity, receipt logs and the expected state transitions. The current adapters consume typed fixture observations. They do not establish independent RPC authenticity or live confirmation depth.

Local recipient and sender bindings must not be described as contract-enforced rules. The contract gates asset, action, limits, validity, revocation and freeze. Live operation still requires fresh API and independent chain evidence plus a separately authorized signing route.

## MCP compatibility

The simulation was tested with the external Model Context Protocol Inspector 2.6.0 over stdio. Verification included discovery, planning, preflight, owner HTTP approval, execution, replay across client processes, revocation and receipt retrieval. The test used a separate temporary client configuration and memory-only secret storage.

The generated .local-demo/mcp-config.json defines two independent stdio servers. The simulation server exposes get_context, plan_transfers, preflight_plan, execute_approved_plan and get_receipt. The separate Sepolia preview server exposes get_context, plan_execute, preflight, execute_approved and get_receipt. Neither exposes owner approval, grant or revoke as an agent tool. A client should launch the exact generated command and arguments. Compatibility with other MCP clients is unverified.

## Verification and distribution

See [verification results](VERIFICATION.md), [AI contribution disclosure](AI-DISCLOSURE.md), [license](LICENSE) and [third-party notices](THIRD-PARTY-NOTICES.md). The portable test runner explicitly selects public application and integration tests. It does not discover native wallet or historical evidence scripts.

This repository is the public source copy of a reviewed local package, and it has no public demo URL. The package's evidence reports and its local Git bundle stay outside the repository. The repository must not be represented as a completed live competition entry.
