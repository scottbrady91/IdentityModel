using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
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
    
    internal EdDsaParameters(AsymmetricCipherKeyPair keyPair, string curve) : this(curve)
    {
        if (keyPair == null) throw new ArgumentNullException(nameof(keyPair));
        
        if (curve == ExtendedSecurityAlgorithms.Curves.Ed25519)
        {
            D = ((Ed25519PrivateKeyParameters) keyPair.Private).GetEncoded();
            X = ((Ed25519PublicKeyParameters) keyPair.Public).GetEncoded();
        }
        else if (curve == ExtendedSecurityAlgorithms.Curves.Ed448)
        {
            D = ((Ed448PrivateKeyParameters) keyPair.Private).GetEncoded();
            X = ((Ed448PublicKeyParameters) keyPair.Public).GetEncoded();
        }
        else
        {
            throw new NotSupportedException("Unsupported EdDSA curve");
        }
    }
    
    public byte[] D { get; set; }
    public byte[] X { get; set; }
    public string Curve { get; }

    public void Validate()
    {
        if ((D == null || D.Length == 0) && (X == null || X.Length == 0)) throw new CryptographicException("Invalid EdDSA parameters - missing keys");
        
        if (D != null)
        {
            if (Curve == ExtendedSecurityAlgorithms.Curves.Ed25519 && (D.Length != 32 && D.Length != 32*2)) throw new CryptographicException("Invalid key length. Must be 32 bytes.");
            if (Curve == ExtendedSecurityAlgorithms.Curves.Ed448 && (D.Length != 57 && D.Length != 57*2)) throw new CryptographicException("Invalid key length. Must be 57 bytes.");
        }

        if (X != null)
        {
            if (Curve == ExtendedSecurityAlgorithms.Curves.Ed25519 && X.Length != 32) throw new CryptographicException("Invalid key length. Must be 32 bytes.");
            if (Curve == ExtendedSecurityAlgorithms.Curves.Ed448 && X.Length != 57) throw new CryptographicException("Invalid key length. Must be 57 bytes.");
        }
    }
}