using System;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Samples.AspNetCore;

public class SampleOptions
{
    public readonly EdDsaSecurityKey EdDsaPublicKey = new EdDsaSecurityKey(
        EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) {X =Convert.FromBase64String("doaS7QILHBdnPULlgs1fX0MWpd1wak14r1yT6ae/b4M=")}));
        
    public readonly EdDsaSecurityKey EdDsaPrivateKey= new EdDsaSecurityKey(
        EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) {D =Convert.FromBase64String("TYXei5+8Qd2ZqKIlEuJJ3S50WYuocFTrqK+3/gHVH9B2hpLtAgscF2c9QuWCzV9fQxal3XBqTXivXJPpp79vgw==")}));
}