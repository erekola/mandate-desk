# Advisory check for the vendored signing bundle

`ethers.umd.min.cjs` is vendored, not an npm dependency. `package.json` declares no dependencies and `.github/dependabot.yml` tracks only GitHub Actions, so neither `npm audit` nor Dependabot ever inventories this file or the libraries bundled inside it.

`tools/check-vendor-advisories.mjs` runs the OSV.dev part of this check for all five components listed below, including the four bundled ones (MD-07): `node tools/check-vendor-advisories.mjs` reads their name and version straight from `sbom.json`, queries `https://api.osv.dev/v1/querybatch` once for all of them, and prints one `OK` or `FOUND` line per component plus a `Last run` line to paste below. It needs network access, so this repository's own tests and CI never run it (see "Tests" in `SECURITY.md`); it is a tool to run by hand, not a scheduled job. The three checks in "How to check" below that OSV.dev does not cover (the GitHub Advisory Database search, the ethers security page and `npm audit` against the top-level version) stay manual.

## Components and versions

`sbom.json` in this folder lists the components with their sources. Check each of these exact name and version pairs:

| Component | Version |
| --- | --- |
| ethers | 6.17.0 |
| @noble/hashes | 1.3.2 |
| @noble/curves | 1.2.0 |
| @adraffy/ens-normalize | 1.11.1 |
| aes-js | 4.0.0-beta.5 |

## How to check

Run these from a machine that may reach the network. This repository's own tests and CI never do.

1. Search the GitHub Advisory Database once per component: `https://github.com/advisories?query=ecosystem%3Anpm+affects%3A<name>`, for example `https://github.com/advisories?query=ecosystem%3Anpm+affects%3Aethers`.
2. Query the OSV.dev API once per component. It needs no key: `curl -s -X POST https://api.osv.dev/v1/query -d '{"package":{"name":"<name>","ecosystem":"npm"},"version":"<version>"}'`
3. Read the upstream advisory page for ethers itself: `https://github.com/ethers-io/ethers.js/security`.
4. For the npm advisory database, audit the top-level version in a throwaway folder outside this repository: `mkdir /tmp/x && cd /tmp/x && npm init -y && npm install ethers@6.17.0 --no-save && npm audit`. That audits the versions npm resolves for ethers today. It does not audit the versions bundled inside the UMD build, which never went through npm's dependency graph here, so steps 1 and 2 are the check for those.

## What this does not prove

A clean result is an advisory check and not a cryptographic audit of the vendored bytes. It also does not cover a vulnerability disclosed after the check was run. Run it again before vendoring a new ethers version, and from time to time in between, because nothing here watches for a new advisory.

Last run: 2026-09-26, during an external hostile source audit of this repository, matched the bundle against the upstream release without querying an advisory database for the four bundled libraries. Last run: 2026-09-28T12:58:22.616Z, OSV.dev, 5/5 components queried (ethers, @noble/hashes, @noble/curves, @adraffy/ens-normalize, aes-js), no advisory found for any of them (`node tools/check-vendor-advisories.mjs`).
