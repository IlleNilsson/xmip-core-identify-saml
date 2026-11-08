# xmip-core-identify-saml

Identify by saml: reads a SAML 2.0 assertion's subject and issuer, unverified, from a posted response or from the content, with the assertion riding as proof for the second gate. A technology of [xmip-core-identify](https://github.com/IlleNilsson/xmip-core-identify).

The scan follows the nesting: the `Issuer`, the `Subject`'s `NameID` and the
attribute statements it reads are the assertion's own children, the same ones
`authenticate/saml` reads from the verified assertion, so a `Subject` planted
in the unsigned `Signature` is never the claim.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
