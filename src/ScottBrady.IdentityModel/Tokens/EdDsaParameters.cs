using System;
using System.Security.Cryptography;
using ScottBrady.IdentityModel.Crypto;

namespace ScottBrady.IdentityModel.Tokens;

public class EdDsaParameters
{
    public EdDsaParameters(string curve)
    {
        if (string.IsNullOrWhiteSpace(curve)) throw new ArgumentNullException(nameof(curve));
        if (curve != ExtendedSecurityAlgorithms.Curves.Ed25519 && curve != ExtendedSecurityAlgorithms.Curves.Ed448) throw new NotSupportedException("Unsupported curve");
        Curve = curve;
    }
    
    // TODO: ctor for signing key? 64 bytes, concatenation of private and public key? https://github.com/openssl/openssl/issues/6357
    
    public byte[] D { get; init; }
    public byte[] X { get; init; }
    public string Curve { get; }

    public void Validate()
    {
        if ((D == null || D.Length == 0) && (X == null || X.Length == 0)) throw new CryptographicException("Invalid EdDSA parameters - missing keys");
        
        if (D != null)
        {
            if (Curve == ExtendedSecurityAlgorithms.Curves.Ed25519 && D.Length != 32 && D.Length != 32*2) throw new CryptographicException("Invalid key length. Must be 32 bytes.");
            if (Curve == ExtendedSecurityAlgorithms.Curves.Ed448 && D.Length != 57 && D.Length != 57*2) throw new CryptographicException("Invalid key length. Must be 57 bytes.");
        }

        if (X != null)
        {
            if (Curve == ExtendedSecurityAlgorithms.Curves.Ed25519 && X.Length != 32) throw new CryptographicException("Invalid key length. Must be 32 bytes.");
            if (Curve == ExtendedSecurityAlgorithms.Curves.Ed448 && X.Length != 57) throw new CryptographicException("Invalid key length. Must be 57 bytes.");
        }
    }
}