using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Samples.AspNetCore;

public class SampleOptions
{
    private static readonly EdDsa _key = EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519);
    
    public readonly EdDsaSecurityKey EdDsaPublicKey = new EdDsaSecurityKey(_key);
    public readonly EdDsaSecurityKey EdDsaPrivateKey= new EdDsaSecurityKey(_key);
}