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
    internal EdDsaParameters Parameters { get; private init; }

    private EdDsa() { }

    public static EdDsa Create(EdDsaParameters parameters)
    {
        if (parameters == null) throw new ArgumentNullException(nameof(parameters));

        parameters.Validate();
        return new EdDsa {Parameters = parameters};
    }
        
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

            return new EdDsa {Parameters = new EdDsaParameters(keyPair, curve)};
        }

        if (curve == ExtendedSecurityAlgorithms.Curves.Ed448)
        {
            var generator = new Ed448KeyPairGenerator();
            generator.Init(new Ed448KeyGenerationParameters(new SecureRandom()));
            var keyPair = generator.GenerateKeyPair();

            return new EdDsa {Parameters = new EdDsaParameters(keyPair, curve)};
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
        
    public byte[] Sign(byte[] input)
    {
        if (input == null) throw new ArgumentNullException(nameof(input));
        
        var signer = CreateSigner();
        signer.Init(true, CreatePrivateKeyParameter());
        signer.BlockUpdate(input, 0, input.Length);

        return signer.GenerateSignature();
    }

    public bool Verify(byte[] input, byte[] signature)
    {
        if (input == null) throw new ArgumentNullException(nameof(input));
        if (signature == null) throw new ArgumentNullException(nameof(signature));
        
        var validator = CreateSigner();
        validator.Init(false, CreatePublicKeyParameter());
        validator.BlockUpdate(input, 0, input.Length);

        return validator.VerifySignature(signature);
    }

    private AsymmetricKeyParameter CreatePrivateKeyParameter()
    {
        return Parameters.Curve switch
        {
            ExtendedSecurityAlgorithms.Curves.Ed25519 => new Ed25519PrivateKeyParameters(Parameters.D, 0),
            ExtendedSecurityAlgorithms.Curves.Ed448 => new Ed448PrivateKeyParameters(Parameters.D, 0),
            _ => throw new NotSupportedException()
        };
    }

    private AsymmetricKeyParameter CreatePublicKeyParameter()
    {
        return Parameters.Curve switch
        {
            ExtendedSecurityAlgorithms.Curves.Ed25519 => new Ed25519PublicKeyParameters(Parameters.X, 0),
            ExtendedSecurityAlgorithms.Curves.Ed448 => new Ed448PublicKeyParameters(Parameters.X, 0),
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
}