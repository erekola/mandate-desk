# AI contribution disclosure

Erik directed the product goals, selected the work to complete and set the accessibility, data-handling and authorization requirements. Codex generated and modified application code, tests, documentation and packaging material. Fable assisted with earlier code review. Further Codex agents reviewed the new transaction validation and recovery work. Claude prepared this public repository copy. It replaced the fixture recipient with a synthetic address and updated the documentation to match. A Claude session then implemented the live Sepolia path on 14 September 2026. Codex audited that path as round A1 and found it not ready for a run, and Fable fixed every finding and added a test for each fix. A second Fable audit on 15 September 2026 checked the fixes and made two corrections, one in the signer launcher and one in a test assertion. A Codex re-check the same day left three findings open with two design decisions, and Fable implemented them in a third round with a test for each. A second Codex re-check the same day left five findings open, and Fable implemented them in a fourth round with a test for each.

The implementation includes substantial AI-generated code. This disclosure does not claim that Erik hand-wrote that code. Agent review and passing tests do not guarantee security, correctness in every environment or eligibility for an award.

Brickken's published campaign guidance permits AI tools but excludes fully AI-generated submissions without meaningful developer contribution. The organizer decides how that rule applies to this work. This repository makes no advance claim of eligibility.

Source: [Build with Brickken campaign guidance](https://dev.to/stefan_gherghe_22/build-with-brickken-dev-campaign-3pj1).
