# poc-wasabi-credential-count

PoC for a **dropped presentation-count guard** in `WabiSabi.Native.CredentialIssuer`
(the native KVAC issuer shipped in the `WabiSabi` 1.3.0 NuGet package, source
[zkSNACKs/NWabiSabi](https://github.com/zkSNACKs/NWabiSabi)), as wired into the
WalletWasabi coordinator by commit `f8e1d4d` ("Make coordinator use the native WabiSabi").

This repository proves the **regression** and states, honestly, exactly how far it does
and does not reach toward an exploit. It runs entirely locally and does not touch any live
coordinator.

## TL;DR

- **Confirmed:** the audited managed issuer rejects any non-null credential request that
  does not present exactly 2 credentials; the native issuer that replaced it on the
  coordinator path has **no such check**, and the C library reads a **fixed 2**
  presentations from fixed byte offsets. A request declaring fewer than 2 presentations
  makes the C code read its "second presentation" from later, attacker-controlled bytes.
- **Not demonstrated:** a working credential double-spend. That would require the native
  issuer to *accept* such a request, which needs the smuggled second presentation to be a
  genuinely-issued credential with a verifying proof while the *same bytes* also serialize
  the request's other fields. A bounded search did not achieve acceptance (see below).
- **Honest severity:** a missing-input-validation regression from the audited managed
  issuer (defense-in-depth). It becomes High **only if** someone demonstrates acceptance
  (the credential double-spend); this PoC does not.

## The chain

| Layer | Guard on `Presented.Count`? | Where |
|---|---|---|
| Managed issuer (replaced) | yes — exactly 2 for a non-null request | `csharp/WabiSabi/CredentialIssuer.cs:127-134` |
| Native wrapper (live) | **no** | `csharp/WabiSabi/Native/CredentialIssuer.cs` |
| C library | **no** — fixed 2-slot read | `c/src/ffi.c:548`, `c/src/issuer.c:141` |
| Coordinator (`Arena`) | validates `Requested.Count` only, never `Presented.Count` | WalletWasabi `Arena.Partial.cs:320-328` |
| Live path | coordinator round uses the native issuer | WalletWasabi `Round.cs` (`using CredentialIssuer = WabiSabi.Native.CredentialIssuer`) |

## What the PoC proves

Run it (below); it prints four sections:

1. **CLAIM 1 [PROVEN]** — feeding `Presented.Count ∈ {0,1,2,3}` to both issuers: managed
   rejects `{0,1,3}` with its explicit *count* guard, native never mentions a count and
   instead reaches the C parser/verifier. Regression confirmed.
2. **CLAIM 2 [CODE-PROVEN]** — the C library reads exactly `WABISABI_CREDENTIAL_COUNT` (2)
   presentations regardless of the declared count, and builds 2 show-statements.
   Corroborated by the native rejection being a *parse* error on the second (overrun)
   presentation for `Presented.Count=1`.
3. **CLAIM 3 [CODE-PROVEN mechanism]** — double-spend prevention lives in the wrapper and
   records serials only for the *declared* presentations; the C library tracks none. The
   serial `S = Randomness·Gs` is fixed per credential, so an unburned serial stays
   re-presentable. On a *rejected* request the wrapper rolls the serial back, so the
   desync only yields an unburned serial if native *accepts*.
4. **IMPACT [NOT DEMONSTRATED]** — a bounded search for a native-accepted
   `Presented.Count<2` request. In this PoC it does **not** succeed: the open obstacle is
   an alignment + proof fixed-point (the same bytes must be a valid second presentation,
   the request's commitments, and verifying proofs, all under one batched Fiat-Shamir
   challenge).

## Run

```
./setup.sh                         # pins NWabiSabi @ WabiSabi-1.3.0 source, fetches libwabisabi.so, adds an InternalsVisibleTo shim
dotnet run --project Poc -c Release
```

Requires the .NET 10 SDK and Linux x64 (the fetched native binary is `linux-x64`).

## Suggested fix (upstream: zkSNACKs/NWabiSabi)

1. **Primary:** restore the count guards in `WabiSabi.Native.CredentialIssuer.HandleRequest`,
   mirroring managed `CredentialIssuer.cs:118-134` — reject `Presented.Count != 2` for a
   non-null request (`!= 0` for a null request) and `Requested.Count` off the expected value.
2. **FFI hardening:** reject when `off != req_len` after parsing, and/or add an explicit
   `n_presented` field to the wire format instead of the hardwired 2.
3. **Defense-in-depth:** validate `Presented.Count` in WalletWasabi's `Arena` for every
   phase (it already validates `Requested.Count`).

## Scope / honesty

The bug is a real regression introduced in the audited window. This PoC deliberately does
**not** claim a working double-spend, because it could not produce one. If you extend it to
a native-accepted `Presented.Count<2` request, the CLAIM-3 mechanism turns it into a
credential double-spend (within-round value inflation); Bitcoin-level value conservation
would still cap direct theft (an inflated coinjoin aborts).
