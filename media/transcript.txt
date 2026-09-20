# Recorded simulation transcript

This walkthrough runs the local app and records its observed results. Recording is limited to the demonstration canvas. MDT is a synthetic token with no monetary value.

Observed local app results. No blockchain transaction is broadcast.

An agent requests. The owner decides.

The agent can prepare a transfer. Approval belongs to the owner workspace. The same checks serve the browser and the scoped MCP tools.

The owner sets a bounded mandate.

60 MDT per transfer. 100 MDT in total. Only listed recipients are allowed. Creating a mandate preserves previous activity and demo balances.

Review the request before approval.

30 MDT passes the local checks. The owner reviews the recipient and the complete plan hash. A changed plan cannot reuse the original approval.

One approved transfer is simulated.

The app rechecks the approval and current mandate before applying 30 MDT to the ledger. The receipt records the observed balances before and after.

A retry returns the same receipt.

The same request ID and plan hash return the existing result. The balance stays unchanged. An ID reused for a different request is rejected.

80 MDT is denied locally.

The request exceeds the limit of 60 MDT per transfer. No approval or balance change follows. Enforcing layer: local simulation policy.

The remaining budget is checked too.

50 MDT succeeds. A following request for 25 MDT exceeds the 20 MDT remaining. Two accepted transfers have now used 80 MDT in total.

Revocation blocks the next request.

The owner revokes the mandate once. A request for 1 MDT is then denied. Enforcing layer: local mandate state. There is no failed chain transaction.

The Sepolia path has its own boundary.

Unsigned preparation is separate from this ledger. A live run needs fresh checks and an authorized signer. The package includes exact transaction validation, recovery and semantic postcheck code with fixture tests.
