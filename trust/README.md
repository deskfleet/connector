# Trust anchors

`allowed_signers` contains only public Ed25519 verification keys, read from the existing owner-controlled release workflow's `CONNECTOR_RELEASE_ALLOWED_SIGNERS` repository variable on 12 November 2026. No private signing key is stored here.

`bootstrap-release.json` pins the identity of the independently signature-verified live version 55 publication at initialization. It prevents an empty public index from being bootstrapped with an older feed or a different version-55 package. Later runs compare against all existing releases as well.

Key rotation and replacement of this baseline require maintainer review. A key supplied by the same remote feed is not a new trust anchor.
