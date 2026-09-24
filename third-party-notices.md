# Third-party notices

The application uses Node.js built-in modules. Node.js is a separately installed prerequisite. Its executable is not part of this repository.

The included ethers 6.17.0 browser bundle is used by the offline ABI tests and by the live signer in tools/live-signer.mjs, which unlocks the two test keystores and signs with it. Its original MIT license and copyright notice are preserved at vendor/ethers-6.17.0/LICENSE.md. The bundle is unchanged. Its SHA-256 is 532950515fd29ae9f7a21ceb2b68100815024d7944c3d5a92246d5b900bd703b. The accompanying artifact manifest records the exact upstream archive entries used. Mandate Desk's license does not replace this third-party notice.

The event signatures and public contract interfaces used by fixture tests were compared with the verified executor and registry interfaces on Sepolia Blockscout. The repository does not redistribute those contracts' source code or claim ownership of Brickken's contracts, name or documentation.

MCP Inspector was used as an external verification client. FFmpeg was used to inspect and encode the demonstration media. Neither development tool is bundled with the application. The recorded images and captions are produced by the Mandate Desk demo renderer from local test results.

Public interface references: [executor](https://eth-sepolia.blockscout.com/address/0xff666CcD01541Cd7abCABB70Dba1cfFEc8C01d9B?tab=contract), [registry](https://eth-sepolia.blockscout.com/address/0xD68E1bb972cA4EF7F5764FBf6d685a6DfC26778e?tab=contract).
