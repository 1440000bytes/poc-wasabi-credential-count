# poc-wasabi-credential-count

A dropped presentation-count guard in `WabiSabi.Native.CredentialIssuer` (the native KVAC
issuer shipped in the `WabiSabi` 1.3.0 NuGet package, source
[zkSNACKs/NWabiSabi](https://github.com/zkSNACKs/NWabiSabi)), wired into the WalletWasabi
coordinator by commit `f8e1d4d` ("Make coordinator use the native WabiSabi").

## The regression

The managed reference issuer (`WabiSabi.Crypto.CredentialIssuer`, lines 127-134) rejects any
non-null credential request that does not present exactly `ProtocolConstants.CredentialNumber`
(2) credentials. The native issuer that replaced it on the coordinator path enforces no such
check, and the C library reads a **fixed 2** presentations from fixed byte offsets.

| Layer | Guard on `Presented.Count`? | Where |
|---|---|---|
| Managed issuer (replaced) | yes — exactly 2 for a non-null request | `csharp/WabiSabi/CredentialIssuer.cs:127-134` |
| Native wrapper (live) | no | `csharp/WabiSabi/Native/CredentialIssuer.cs` |
| C library | no — fixed 2-slot read | `c/src/ffi.c:548`, `c/src/issuer.c:141` |
| Coordinator (`Arena`) | validates `Requested.Count` only, never `Presented.Count` | WalletWasabi `Arena.Partial.cs:320-328` |
| Live path | coordinator round uses the native issuer | WalletWasabi `Round.cs` (`using CredentialIssuer = WabiSabi.Native.CredentialIssuer`) |

## What the PoC proves

Running it against the real 1.3.0 code prints three results:

1. **The count guard is gone.** Feeding `Presented.Count ∈ {0,1,2,3}` to both issuers: the
   managed issuer rejects `{0,1,3}` with its explicit presentation-count error; the native
   issuer has no such check and instead runs the request into the C parser/verifier.

2. **The C library reads a fixed 2 presentations** from fixed offsets regardless of how many
   were declared, and builds 2 credential-show statements (`c/src/ffi.c:548`,
   `c/src/issuer.c:141`). With `Presented.Count=1` the native issuer parses a second
   presentation out of the bytes that follow the declared one.

3. **Serial recording is bounded by the declared count.** Double-spend prevention lives in
   the wrapper (`Native/CredentialIssuer.cs:89-101`), which records serials only for the
   declared presentations; the C library tracks none. The serial `S = Randomness·Gs` is fixed
   per credential (`Credential.cs:53`). So the number of serials the wrapper records can be
   fewer than the number of presentations the C verifier processes.

## Run

```
./setup.sh                         # pins NWabiSabi @ WabiSabi-1.3.0 source, fetches libwabisabi.so, adds an InternalsVisibleTo shim
dotnet run --project Poc -c Release
```

Requires the .NET 10 SDK and Linux x64 (the fetched native binary is `linux-x64`).

## Fix (upstream: zkSNACKs/NWabiSabi)

1. Restore the count guards in `WabiSabi.Native.CredentialIssuer.HandleRequest`, mirroring
   managed `CredentialIssuer.cs:118-134`: reject `Presented.Count != 2` for a non-null request
   (`!= 0` for a null request) and `Requested.Count` off the expected value.
2. In the FFI, reject when `off != req_len` after parsing, and/or add an explicit
   `n_presented` field to the wire format instead of the hardwired 2.
3. In WalletWasabi's `Arena`, validate `Presented.Count` in every phase (it already validates
   `Requested.Count`).
