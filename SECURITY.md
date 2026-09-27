# Security policy

## Supported versions

Mandate Desk is a local reference implementation without releases. Only the current `main` branch is supported, and a fix lands there.

| Version | Supported |
| ------- | --------- |
| Current `main` | :white_check_mark: |

The live Sepolia run of 15 September 2026 keeps the code identity it was approved for. A later revision of `main` does not change that run's evidence or extend its approval.

## What runs and what it touches

The application runs on the owner's own computer and listens only on the loopback address. It has no remote authentication and no Internet-facing deployment mode. The public demo page is a static page that makes no API call and sends no transaction.

Without `--live` the signing route is unavailable, and an execution attempt reports `SIGNING_ROUTE_UNAVAILABLE`. With `--live` the owner starts a separate signer process. That process decrypts the two test keystores and keeps the Brickken API key in its own memory. The repository holds no live keystore, no live wallet and no API key, and it holds no signed transaction. Its tests use the publicly known Hardhat development keys.

## Trust boundary

The data folder, `.local-demo` by default, holds the live workspace, the recovery journal, the lock files, the signer endpoint record and the evidence of each run. Only the owner's own account should be able to write it. The code checks what it reads there. It does not defend against a local process that can already change that folder.

A lock path that is a symbolic link, a junction or a second name of another file is refused and left in place. After the open, the path must name the file that the exclusive handle holds.

The signer endpoint record must match its exact format and name the code identity of the process that reads it. Before every write the workspace also asks the running signer for its approval and its code identity. The record is local and says what it says about itself, so these checks stop a stale or mismatched signer and cannot prove that a signer is genuine.

## Evidence export

`tools/export-live-evidence.mjs` publishes the evidence of one run under `verification/`. Every JSON file in the package is checked against a closed field schema for its kind, nested objects and array elements included, and a field outside the schema stops the export. The export also refuses a `signedTransaction` field anywhere and any member that is not a bounded regular file. It builds and checks the whole package before the folder exists, so a refused export leaves no partial package behind.

## Tests

GitHub Actions runs `node tools/check-demo.mjs` on Windows for every push and pull request. The job has read-only access to the repository and no secrets. The suite uses a fake chain and a fake gateway and makes no network call.

## Reporting a vulnerability

If you discover a security vulnerability, please report it privately by emailing **info@turva.dev**.

Please do not open a public issue for security reports.

You can expect an initial response within a few days. If the issue is confirmed, a fix will be prioritized and you'll be kept informed of progress.
