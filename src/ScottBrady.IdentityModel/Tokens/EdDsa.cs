using System;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using ScottBrady.IdentityModel.Crypto;

namespace ScottBrady.IdentityModel.Tokens;

public class EdDsa : AsymmetricAlgorithm
{
    internal EdDsaParameters Parameters { get; private init; }
    internal AsymmetricKeyParameter PrivateKeyParameter { get; private init; }
    internal AsymmetricKeyParameter PublicKeyParameter { get; private init; }

    private EdDsa() { }

    public static EdDsa Create(EdDsaParameters parameters)
    {
        if (parameters == null) throw new ArgumentNullException(nameof(parameters));
        
        parameters.Validate();
        return new EdDsa
        {
            Parameters = parameters,
            PrivateKeyParameter = CreatePrivateKeyParameter(parameters),
            PublicKeyParameter = CreatePublicKeyParameter(parameters)
        };
    }
        
    /// <summary>
    /// Create new key for EdDSA.
    /// </summary>
    /// <param name="curve">Create key for curve Ed25519 or Ed448.</param>
    public new static EdDsa Create(string curve)
    {
        if (string.IsNullOrWhiteSpace(curve)) throw new ArgumentNullException(nameof(curve));

        IAsymmetricCipherKeyPairGenerator generator;
        if (curve == ExtendedSecurityAlgorithms.Curves.Ed25519)
        {
            generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            
        }
        else if (curve == ExtendedSecurityAlgorithms.Curves.Ed448)
        {
            generator = new Ed448KeyPairGenerator();
            generator.Init(new Ed448KeyGenerationParameters(new SecureRandom()));
        }
        else
        {
            throw new NotSupportedException("Unsupported EdDSA curve");  
        }
        
        var keyPair = generator.GenerateKeyPair();
        return new EdDsa
        {
            Parameters = new EdDsaParameters(keyPair, curve),
            PrivateKeyParameter = keyPair.Private,
            PublicKeyParameter = keyPair.Public
        };
    }

    /// <summary>
    /// Create EdDSA from JSON Web Key (jwk).
    /// </summary>
    /// <param name="jwk">String containing JSON Web Key.</param>
    public static EdDsa CreateFromJwk(string jwk)
    {
        throw new NotImplementedException();
    }

    public override string KeyExchangeAlgorithm => null;
    public override string SignatureAlgorithm => ExtendedSecurityAlgorithms.EdDsa;
    public override int KeySize => Parameters.D?.Length ?? Parameters.X?.Length ?? throw new InvalidOperationException("Missing EdDsa key");

    public override KeySizes[] LegalKeySizes => Parameters.Curve switch
    {
        ExtendedSecurityAlgorithms.Curves.Ed25519 => new[] { new KeySizes(32, 32, 0) },
        ExtendedSecurityAlgorithms.Curves.Ed448 => new[] { new KeySizes(57, 57, 0) },
        _ => throw new NotSupportedException()
    };

    public byte[] Sign(byte[] input)
    {
        if (input == null) throw new ArgumentNullException(nameof(input));
        
        var signer = CreateSigner();
        signer.Init(true, PrivateKeyParameter);
        signer.BlockUpdate(input, 0, input.Length);

        return signer.GenerateSignature();
    }

    public bool Verify(byte[] input, int inputOffset, int inputLength, byte[] signature, int signatureOffset, int signatureLength)
    {
        
        if (input == null) throw new ArgumentNullException(nameof(input));
        if (signature == null) throw new ArgumentNullException(nameof(signature));
        if (inputLength <= 0) throw new ArgumentException($"{nameof(inputLength)} must be greater than 0");
        if (signatureLength <= 0) throw new ArgumentException($"{nameof(signatureLength)} must be greater than 0");
        
        return Verify(input.Skip(inputOffset).Take(inputLength).ToArray(), signature.Skip(signatureOffset).Take(signatureLength).ToArray());
    }
    
    public bool Verify(byte[] input, byte[] signature)
    {
        if (input == null) throw new ArgumentNullException(nameof(input));
        if (signature == null) throw new ArgumentNullException(nameof(signature));
        
        var validator = CreateSigner();
        validator.Init(false, PublicKeyParameter);
        validator.BlockUpdate(input, 0, input.Length);

        return validator.VerifySignature(signature);
    }

    private static AsymmetricKeyParameter CreatePrivateKeyParameter(EdDsaParameters parameters)
    {
        if (parameters.D == null) return null;
        
        return parameters.Curve switch
        {
            ExtendedSecurityAlgorithms.Curves.Ed25519 => new Ed25519PrivateKeyParameters(parameters.D),
            ExtendedSecurityAlgorithms.Curves.Ed448 => new Ed448PrivateKeyParameters(parameters.D),
            _ => throw new NotSupportedException()
        };
    }

    private static AsymmetricKeyParameter CreatePublicKeyParameter(EdDsaParameters parameters)
    {
        if (parameters.X == null) return null;
        
        return parameters.Curve switch
        {
            ExtendedSecurityAlgorithms.Curves.Ed25519 => new Ed25519PublicKeyParameters(parameters.X),
            ExtendedSecurityAlgorithms.Curves.Ed448 => new Ed448PublicKeyParameters(parameters.X),
            _ => throw new NotSupportedException()
        };
    }

    private ISigner CreateSigner()
    {
        return Parameters.Curve switch
        {
            ExtendedSecurityAlgorithms.Curves.Ed25519 => new Ed25519Signer(),
            ExtendedSecurityAlgorithms.Curves.Ed448 => new Ed448Signer(Array.Empty<byte>()),
            _ => throw new NotSupportedException()
        };
    }
    
    public override void ImportFromEncryptedPem(ReadOnlySpan<char> input, ReadOnlySpan<char> password) => throw new NotImplementedException();
    public override void ImportFromEncryptedPem(ReadOnlySpan<char> input, ReadOnlySpan<byte> passwordBytes) => throw new NotImplementedException();
    public override void ImportFromPem(ReadOnlySpan<char> input) => throw new NotImplementedException();
}