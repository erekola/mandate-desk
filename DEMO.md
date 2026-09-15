# Demo guide

Use the complete start block in README.md. The application runs locally with synthetic MDT and saves its own history. The recorded walkthrough in the media directory shows actual API responses presented on the application's demonstration canvas. Captions are visible in the recording. Its transcript reproduces those captions.

## Owner walkthrough

Open the owner workspace at http://127.0.0.1:4327/. A fresh clone starts with 1000 MDT and a 60 MDT per-transfer limit within a total of 100 MDT. Keep one of the listed demo recipients.

Prepare 30 MDT. Open the review and inspect the recipient, amount and full plan hash. Approve the plan, then execute it. The receipt reports a simulated transfer and the owner balance becomes 970 MDT. The receipt contains no blockchain transaction hash.

An agent may repeat that same request ID and plan hash through the simulation MCP execution tool. It receives the existing receipt. The owner balance stays at 970 MDT. Changing the request under the same ID is rejected.

The Run example sequence button executes a fresh mandate sequence while preserving prior balances and history. It accepts 30, denies 80, accepts 50 and denies 25. Total mandate use becomes 80 MDT. Revoking the mandate then denies a request for 1 MDT. The denied requests identify the local enforcing rule. Each activity entry has a centered View details button and Refresh state is centered above the history.

The owner can create a new demo mandate to continue after revocation. That resets its usage counter. Previous receipts and demo balances stay. A fresh 1000 MDT ledger needs a new empty data directory. Existing data must not be deleted to imitate a clean first run.

## Separate Sepolia preview

Open http://127.0.0.1:4327/integration. The page labels its fixture provenance and displays unsigned setup, approval, grant, execution and revocation envelopes. Review the complete preview hash before local approval. Attempting execution stops at SIGNING_ROUTE_UNAVAILABLE. This is the intended result with the packaged adapter.

The proposed live slice is Ethereum Sepolia, chain 11155111, transferring 0.01 test USDC with a per-transfer cap of 10000 raw units, a cumulative cap of 15000 and an allowance of 15000. The transaction-cap probe requests 11000 raw units. After the transfer, the cumulative probes request 5000 and 6000 raw units. These amounts belong to the separate live proposal and are unrelated to the 30/80/50/25 MDT simulation sequence.

The simulation and the preparation page have no live transaction, so they show no transaction explorer links. A local or API denial must never be given an invented transaction hash. The six confirmed transactions of the live run of 15 September 2026 are listed with their explorer links in verification/sepolia-live-c990e8a178b0/transactions.json and http://127.0.0.1:4327/live-demo renders a completed run from its saved state when the application runs with --live. The recording of that page bound to the run is media/mandate-desk-live-run.webm, with its binding record beside it.

## Record the walkthrough again

Open http://127.0.0.1:4327/demo and use Run and record the walkthrough. The application performs the demonstrated local API sequence and records only its canvas. The walkthrough runs for about two minutes. It needs no timed response, microphone or camera. The completed WebM and its hash metadata are saved in the selected demo data directory's recordings folder.

If a result differs from the expected sequence or the browser lacks WebM canvas recording, the page reports the failure. A failed recording is not presented as a successful artifact. Run the walkthrough on a demo ledger with at least 80 MDT available. All accepted transfers are retained as local activity.

## Recovery and limits

A stopped browser does not reset saved application state. Reload the owner page to inspect the recorded receipt before repeating an action. Reuse the original operation identity for an idempotent retry. Keep the server and MCP client pointed at the same data directory.

The integration journal implements offline tests for uncertain broadcasts, duplicate identities, nonce conflicts and changed confirmation blocks. A real signer exists at tools/live-signer.mjs. It serves only the separate live workspace, which runs when the server and the live MCP server are started with --live and the preview workspace never reaches it. Never treat a pending preparation, a local approval or receipt status alone as proof of a verified live transfer.

## Live run recovery and recording

The live route requires a separate owner approval of the plan hash and code identity. The simulation start block above does not start it. Complete setup with that approved identity, then let the agent call execute_approved for the approved execute operation. Wait until its receipt is semantically verified. For the recorded live-demo walkthrough, the agent must call execute_approved a second time with exactly the same operationId. That call records a replay observation through reads. It returns the existing result without signing or sending another transaction.

Finish owner revocation and the allowance reset, then obtain finality from both sources and export the evidence package with the replay included. The live-demo page requires a passed replay before rendering or recording its ten scenes. The server's general recording binding requires the complete run and its matching package, while replay is an additional requirement of this particular walkthrough. If replay is missing or fails, resolve that observation and export again before recording. The binding stored beside the WebM names the hash of SHA256SUMS.json for that exact export.

After an interrupted run, a new plan can report ALLOWANCE_NOT_ZERO in its preflight blockers. Keep that refusal. Inspect the interrupted run and use its cleanup path under its original approved code identity before preparing another run. Cleanup proves the origin of the remaining allowance from both sources. If it cannot attribute the value or finds a foreign approval, it stops for a separate owner decision. A later code correction does not authorize cleanup of an older run under the new identity.

Cleanup reads the allowance and its approval history at a specific block, then reads them again before signing a reset. This protects the observed history up to that block. A foreign approval after the observation can still land before the reset transaction. The remaining window includes signing, any signer queue and journal writes, broadcasting, inclusion and recovery delays. It has no fixed one-block duration and the token's approve operation does not condition its reset on the observed history.

The covered RPC client spaces reads to each source and retries an allowlisted read only after HTTP 429. Its defaults allow three retries, with delays beginning at 500 milliseconds and capped at five seconds. Queue time and retries share the request's existing deadline. Transaction submission is never retried by this policy. Recovery may resend identical signed bytes under its separate journal rules. No fetch preload is needed for this policy.
