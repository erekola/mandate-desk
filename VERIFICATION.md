# Verification record

Prepared on 14 September 2026 and updated on 15 September 2026. This record describes what this public repository proves and where the proof stops. The repository is a curated copy of a reviewed local package. Some results below were measured on the repository's own files. The others are dated results from the reviewed package, and each section says which kind it is.

## Tests on this repository

The portable suite was run on this repository's files on 15 September 2026 with Node.js 24.19.0. The command `node tools/check-demo.mjs` passed 363 of 363 tests, twice, with the same test names both times. The public copy of 14 September 2026 passed 162 of 162 with the same command, and the 201 tests added since cover the live Sepolia path.

## Changes from the reviewed package

One fixture changed. The reviewed package's `integration/demo-proposal.json` named a recipient address that is not published here. Its recipient is now the synthetic address `0x8888888888888888888888888888888888888888`. The project's own encoders rebuilt the transfer intent, calldata, call hash and proposal hash for that address, after first reproducing the original call byte for byte. The proposal hash pinned in `src/brickken-workspace.mjs` was updated to match.

The documentation was updated for the repository. The reviewed package also held submission documents, machine-readable evidence reports, style reports, a local Git bundle and the original WebM recording. They stay with the local package and are not in this repository.

`SHA256-MANIFEST.json` lists the SHA-256 of every other file in the repository.

## External MCP client checks

These checks ran on 14 September 2026 while the reviewed package was prepared, and they were not repeated on this repository. They used `@modelcontextprotocol/inspector` version 2.6.0 over stdio and exercised two separate server routes.

The simulation route covered discovery, current context, planning, preflight, denial before owner approval, owner approval through the loopback HTTP boundary, execution, restart-safe replay, revocation, denial after revocation, receipt retrieval and the final saved state. The replay returned the recorded result without applying the transfer again.

The integration route covered discovery, context, proposal preparation, review before approval, preflight, execution attempt, replay and receipt retrieval. It used offline fixtures. The packaged signing adapter is deliberately unavailable, so the execution attempt ended at `SIGNING_ROUTE_UNAVAILABLE`. The receipt records that no signing, broadcast or chain write was attempted and contains no transaction hash.

The two Inspector reports were kept separate because the synthetic MDT ledger and the Sepolia preparation workspace prove different behavior. A result from one route is not presented as evidence for the other.

## Demonstration media

`media/mandate-desk-demo.mp4` is a 132 second, 1600 by 900 recording of the application canvas using actual local API results. It has no audio. It was recorded from the local application while the reviewed package was prepared, and it shows the simulation with zero blockchain transactions. The final observed frame is held through its caption so the result can be read without a timed interaction.

The video demonstrates the owner review flow, local approval boundary, allowed and denied transfers, idempotent replay, revocation and the saved receipt. A visible local receipt without a chain transaction hash remains a simulation receipt.

`media/mandate-desk-card.png` is a summary card for project listings. It carries the turva.dev wordmark, and its text states the test count and the missing live transaction.

## Semantic and recovery evidence

The final tests exercise exact transaction, receipt, log and block identity checks for action setup, ERC-20 approval, mandate grant, execution and revocation. They also exercise expected state, balance, allowance and cumulative-use changes. Receipt status by itself is insufficient.

Recovery fixtures cover pending, signed, broadcast or uncertain, confirmed and semantically verified journal states. They cover duplicate operation binding, full decoded signed-transaction matching, signed-byte identity, nonce conflicts, unresolved broadcasts, confirmation block-hash changes and restart behavior. An unresolved nonce cannot receive a replacement signature, and only identical signed bytes are eligible for a resend.

These semantic and recovery checks use injected fixtures. The test suite does not load a real wallet, create a real signature, call a live RPC endpoint or broadcast a transaction. The live path can do those things only when started with --live, and it has not been started that way for this repository. Fixture bytes and local hashes are not claimed as live Ethereum transaction hashes. A live result would still need independently retained trusted expectations, fresh chain observations, the exact signed transaction and post-confirmation semantic checks.

## Live Sepolia path

The code of a live Sepolia run is in this repository. It was implemented on 14 September 2026 and audited the same day as round A1, which found eleven defects in recovery, locking, two-source verification, control evidence, cleanup, export completeness and recording metadata. Every finding was fixed with an acceptance test that fails on the audited source and passes on the fixed one, and the suite grew from 313 to 336 tests. A second audit on 15 September 2026 ran the suite twice, replayed the eight root reproductions of round A1 against the fixed source, read every fix against the source and reviewed the path adversarially. It found one low defect, the launcher's argument quoting for a wallet directory that ends in a backslash, and one test assertion that could not fail. Both are fixed in this repository.

An independent re-check of the fixes on 15 September 2026 left three findings open and recorded two design decisions. The lock still compared a record and then acted on the file name in a second step. A recheck of a verified write kept it as a basis for the next write when its depth had fallen below the required two on one source. A control block whose hash one source reported as changed stayed canonical when the other source had no block at that height. The grant verifier rejected a second grant on the same agent and principal pair, so a repeat run stopped after the grant was on chain and cleanup could not revoke it. The code identity hash was stored with a run but never compared again.

A third round on 15 September 2026 implemented all of that. The three live lock files are held through an exclusive file handle that the operating system keeps for the life of the holding process, so a stale takeover or an old release cannot remove a newer holder, and nothing in the protocol compares a record and then acts on the path. Ownership and the source code identity are checked again right before every preparation, signature and send, after the reads that precede them. A dependent write waits until both read sources return every earlier write of the run at the required depth. A control or write block that one source reports with another hash is withdrawn even when the other source has no block at that height, and a missing block never counts as agreement. A grant after a revoked mandate of the same pair verifies from the registry's real state, and cleanup revokes only a mandate it can attribute to the run by receipt, calldata, event and block-bound state on both sources. The owner approves two hashes, the exact plan and the stable identity of the source code, which covers the sorted file table of src, public, tools, the live proposal, the vendored ethers bundle and package.json. The owner, agent and signer processes each compute that identity when they start and refuse a run whose approved identity differs from their own or from the files on disk. A live recording binds to the exported evidence package by the hash of its checksum file. Two independent checks read the round before it was closed. One found that the recording binding and the evidence export ran the completeness rule without checking the code identity, so a process whose files had changed after the run could still bind a recording or export a package. Both now refuse, and the export names the identity it ran with. The suite grew from 336 to 363 tests. The eight root reproductions of round A1 and the counter-tests of the re-check were replayed against this tree, and none of the old behaviour reproduces. The third round has not yet had its own external re-check. No live run has been performed. The repository holds no signed transaction, no wallet, no API key and no chain observation from a run. The tests use a fake chain and a fake gateway.

## Preserved state and authorization

The reviewed package's preparation was checked against the local project on 14 September 2026. The original eleven saved operations, the checkpoint evidence and the guards were unchanged, and the recorded authorization for a later wallet check remained unconsumed. That local state is not part of this repository.

No live authorization was used for the simulation, the Inspector checks, the media build, the documentation or this repository copy. Local approval in the demonstration does not authorize wallet access, signing, broadcast, publication or competition submission.

## Evidence-write deviation

One delegated development run was broader than its brief allowed. It created two new, uniquely named fixture outputs below earlier evidence roots in the local project. Read-only inspection found no pre-existing checkpoint file overwritten. The new outputs were left in place so the deviation would stay visible, and they are in neither the package nor this repository.

The broad development run is not used as a verdict. The results above come from the explicit runs they name.

## Verification limit

This repository supports review of the application, source, tests, three MCP routes and recorded simulation. It does not prove a live Brickken or Ethereum transaction. No hosted deployment, wallet signing, RPC submission or competition submission is represented as complete.
