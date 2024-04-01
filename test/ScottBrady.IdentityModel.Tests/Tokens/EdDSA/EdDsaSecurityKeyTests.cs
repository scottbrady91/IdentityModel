using System;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.EdDSA;

public class EdDsaSecurityKeyTests
{
    [Fact]
    public void ctor_WhenKeyParametersAreNull_ExpectArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new EdDsaSecurityKey(null));
    }
        
    [Fact]
    public void ctor_WhenEd25519PrivateKey_ExpectKeySetAndCorrectCurve()
    {
        var keyPair = GenerateEd25519KeyPair();
        var privateKeyParameters = (Ed25519PrivateKeyParameters)keyPair.Private;
        var edDsa = EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) { D = privateKeyParameters.GetEncoded() });

        var securityKey = new EdDsaSecurityKey(edDsa);

        securityKey.CryptoProviderFactory.CustomCryptoProvider.Should().BeOfType<ExtendedCryptoProvider>();
        securityKey.EdDsa.Should().Be(edDsa);
        securityKey.PrivateKeyStatus.Should().Be(PrivateKeyStatus.Exists);
        securityKey.KeySize.Should().Be(32);

#pragma warning disable 618
        securityKey.HasPrivateKey.Should().BeTrue();
#pragma warning restore 618
    }

    [Fact]
    public void ctor_WhenEd25519PublicKey_ExpectKeySetAndCorrectCurve()
    {
        var keyPair = GenerateEd25519KeyPair();
        var publicKeyParameters = (Ed25519PublicKeyParameters)keyPair.Public;
        var edDsa = EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) { X = publicKeyParameters.GetEncoded() });
        
        var securityKey = new EdDsaSecurityKey(edDsa);
        
        securityKey.CryptoProviderFactory.CustomCryptoProvider.Should().BeOfType<ExtendedCryptoProvider>();
        securityKey.EdDsa.Should().Be(edDsa);
        securityKey.PrivateKeyStatus.Should().Be(PrivateKeyStatus.DoesNotExist);
        securityKey.KeySize.Should().Be(32);

#pragma warning disable 618
        securityKey.HasPrivateKey.Should().BeFalse();
#pragma warning restore 618
    }
        
    private static AsymmetricCipherKeyPair GenerateEd25519KeyPair()
    {
        var keyPairGenerator = new Ed25519KeyPairGenerator();
        keyPairGenerator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        return keyPairGenerator.GenerateKeyPair();
    }
}