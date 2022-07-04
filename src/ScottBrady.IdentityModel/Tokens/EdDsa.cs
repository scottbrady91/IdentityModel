using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using ScottBrady.IdentityModel.Crypto;

namespace ScottBrady.IdentityModel.Tokens;

public class EdDsa
{
    public AsymmetricKeyParameter KeyParameters { get; private set; }
    public string Curve { get; private set; }

    private EdDsa() { }
        
    /// <summary>
    /// Create new key for EdDSA.
    /// </summary>
    /// <param name="curve">Create key for curve Ed25519 or Ed448.</param>
    public static EdDsa Create(string curve)
    {
        if (string.IsNullOrWhiteSpace(curve)) throw new ArgumentNullException(nameof(curve));

        if (curve == ExtendedSecurityAlgorithms.Curves.Ed25519)
        {
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            var keyPair = generator.GenerateKeyPair();
            
            return new EdDsa {KeyParameters = keyPair.Private, Curve = curve};
        }

        if (curve == ExtendedSecurityAlgorithms.Curves.Ed448)
        {
            var generator = new Ed448KeyPairGenerator();
            generator.Init(new Ed448KeyGenerationParameters(new SecureRandom()));
            var keyPair = generator.GenerateKeyPair();
            
            return new EdDsa {KeyParameters = keyPair.Private, Curve = curve};
        }

        throw new NotSupportedException("Unsupported EdDSA curve");
    }

    /// <summary>
    /// Create EdDSA from JSON Web Key (jwk).
    /// </summary>
    /// <param name="jwk">String containing JSON Web Key.</param>
    public static EdDsa CreateFromJwk(string jwk)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Create EdDSA from private key bytes.
    /// </summary>
    /// <param name="privateKey">Private key as byte array. Must be correct length for curve.</param>
    /// <param name="curve">Curve the private key is for (Ed25519 or Ed448).</param>
    /// <exception cref="ArgumentException">Incorrect key length for curve.</exception>
    public static EdDsa CreateFromPrivateKey(byte[] privateKey, string curve)
    {
        if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
        if (string.IsNullOrWhiteSpace(curve)) throw new ArgumentNullException(nameof(curve));
        
        if (curve == ExtendedSecurityAlgorithms.Curves.Ed25519)
        {
            if (privateKey.Length != 32) throw new ArgumentException("Invalid key length. Must be 32 bytes.");
            return new EdDsa {KeyParameters = new Ed25519PrivateKeyParameters(privateKey, 0), Curve = curve};
        }
        
        if (curve == ExtendedSecurityAlgorithms.Curves.Ed448)
        {
            if (privateKey.Length != 57) throw new ArgumentException("Invalid key length. Must be 57 bytes.");
            return new EdDsa {KeyParameters = new Ed448PrivateKeyParameters(privateKey, 0), Curve = curve};
        }
        
        throw new NotSupportedException("Unsupported EdDSA curve");
    }

    public static EdDsa CreateFromPublicKey(byte[] publicKey, string curve)
    {
        if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
        if (string.IsNullOrWhiteSpace(curve)) throw new ArgumentNullException(nameof(curve));
        
        if (curve == ExtendedSecurityAlgorithms.Curves.Ed25519)
        {
            if (publicKey.Length != 32) throw new ArgumentException("Invalid key length. Must be 32 bytes.");
            return new EdDsa {KeyParameters = new Ed25519PublicKeyParameters(publicKey, 0), Curve = curve};
        }
        
        if (curve == ExtendedSecurityAlgorithms.Curves.Ed448)
        {
            if (publicKey.Length != 57) throw new ArgumentException("Invalid key length. Must be 57 bytes.");
            return new EdDsa {KeyParameters = new Ed448PublicKeyParameters(publicKey, 0), Curve = curve};
        }
        
        throw new NotSupportedException("Unsupported EdDSA curve");
    }
        
    public byte[] Sign(byte[] input)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, KeyParameters);
        signer.BlockUpdate(input, 0, input.Length);

        return signer.GenerateSignature();
    }

    public bool Verify(byte[] input, byte[] signature)
    {
        var validator = new Ed25519Signer();
        validator.Init(false, KeyParameters);
        validator.BlockUpdate(input, 0, input.Length);

        return validator.VerifySignature(signature);
    }
}