using System;
using System.Security.Cryptography;
using FluentAssertions;
using Org.BouncyCastle.Crypto.Parameters;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.EdDSA.AsymmetricAlgorithm;

public class EdDsaCreationTests : EdDsaTestBase
{
    [Fact]
    public void FromParameters_WhenParametersAreNull_ExpectArgumentNullException()
        => Assert.Throws<ArgumentNullException>(() => EdDsa.Create((EdDsaParameters) null));
    
    [Fact]
    public void FromParameters_WhenParametersDoNotContainKeys_ExpectCryptographicException()
        => Assert.Throws<CryptographicException>(() => EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519)));
    
    [Fact]
    public void FromParameters_WhenEd25519PrivateKey_ExpectCorrectParameters()
    {
        var bcParameters = (Ed25519PrivateKeyParameters)GenerateEd25519KeyPair().Private;

        var parameters = new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) { D = bcParameters.GetEncoded() };
        var key = EdDsa.Create(parameters);
        
        key.Parameters.Should().Be(parameters);
        key.PrivateKeyParameter.Should().NotBeNull();
        key.PrivateKeyParameter.Should().BeOfType<Ed25519PrivateKeyParameters>();
        key.PrivateKeyParameter.Should().BeEquivalentTo(bcParameters);
        key.PublicKeyParameter.Should().BeNull();
    }
    
    [Fact]
    public void FromParameters_WhenEd448PrivateKey_ExpectCorrectParameters()
    {
        var bcParameters = (Ed448PrivateKeyParameters)GenerateEd448KeyPair().Private;

        var parameters = new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed448) { D = bcParameters.GetEncoded() };
        var key = EdDsa.Create(parameters);
        
        key.Parameters.Should().Be(parameters);
        key.PrivateKeyParameter.Should().NotBeNull();
        key.PrivateKeyParameter.Should().BeOfType<Ed448PrivateKeyParameters>();
        key.PrivateKeyParameter.Should().BeEquivalentTo(bcParameters);
        key.PublicKeyParameter.Should().BeNull();
    }
    
    [Fact]
    public void FromParameters_WhenEd25519PublicKey_ExpectCorrectParameters()
    {
        var bcParameters = (Ed25519PublicKeyParameters)GenerateEd25519KeyPair().Public;

        var parameters = new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) { X = bcParameters.GetEncoded() };
        var key = EdDsa.Create(parameters);
        
        key.Parameters.Should().Be(parameters);
        key.PrivateKeyParameter.Should().BeNull();
        key.PublicKeyParameter.Should().NotBeNull();
        key.PublicKeyParameter.Should().BeOfType<Ed25519PublicKeyParameters>();
        key.PublicKeyParameter.Should().BeEquivalentTo(bcParameters);
    }
    
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void FromCurve_WhenNullOrWhitespaceCurve_ExpectArgumentNullException(string curve)
        => Assert.Throws<ArgumentNullException>(() => EdDsa.Create(curve));

    [Fact]
    public void FromCurve_WhenUnsupportedAlgorithm_ExpectNotSupportedException()
        => Assert.Throws<NotSupportedException>(() => EdDsa.Create("P-521"));
    
    [Theory]
    [InlineData(ExtendedSecurityAlgorithms.Curves.Ed25519, 32)]
    [InlineData(ExtendedSecurityAlgorithms.Curves.Ed448, 57)]
    public void FromCurve_WhenEd25519_ExpectCorrectKeyParameters(string curve, int keyLength)
    {
        var alg = EdDsa.Create(curve);
        alg.Parameters.D.Length.Should().Be(keyLength);
        alg.Parameters.X.Length.Should().Be(keyLength);
    }
}