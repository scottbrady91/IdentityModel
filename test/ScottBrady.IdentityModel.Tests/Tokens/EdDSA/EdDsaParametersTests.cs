using System;
using System.Security.Cryptography;
using FluentAssertions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.EdDSA;

public class EdDsaParametersTests
{
    
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void ctor_WhenCurveIsNullOrWhitespace_ExpectArgumentNullException(string curve)
        => Assert.Throws<ArgumentNullException>(() => new EdDsaParameters(curve));

    [Fact]
    public void Validate_WhenCurveIsInvalid_ExpectNotSupportedException() 
        => Assert.Throws<NotSupportedException>(() => new EdDsaParameters("P-256") {D = new byte[57], X = new byte[57]});

    [Fact]
    public void ctor_ExpectCorrectCurve()
    {
        const string curve = ExtendedSecurityAlgorithms.Curves.Ed448;
        var parameters = new EdDsaParameters(curve);
        parameters.Curve.Should().Be(curve);
    }
    
    [Fact]
    public void ctor_Parameters_WhenKeyPairIsNull_ExpectArgumentNullException()
        => Assert.Throws<ArgumentNullException>(() => new EdDsaParameters(null, ExtendedSecurityAlgorithms.Curves.Ed448));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void ctor_Parameters_WhenCurveIsNullOrWhitespace_ExpectArgumentNullException(string curve)
        => Assert.Throws<ArgumentNullException>(() => new EdDsaParameters(GenerateEd448KeyPair(), curve));

    [Fact]
    public void ctor_Parameters_WhenUnsupportedAlgorithm_ExpectNotSupportedException()
        => Assert.Throws<NotSupportedException>(() => new EdDsaParameters(GenerateEd448KeyPair(), "P-256"));

    [Fact]
    public void ctor_Parameters_WhenEd25519KeyPair_ExpectCorrectParameters()
    {
        var keyPair = GenerateEd25519KeyPair();
        var expectedPrivateKey = ((Ed25519PrivateKeyParameters) keyPair.Private).GetEncoded();
        var expectedPublicKey = ((Ed25519PublicKeyParameters) keyPair.Public).GetEncoded();

        var parameters = new EdDsaParameters(keyPair, ExtendedSecurityAlgorithms.Curves.Ed25519);

        parameters.Curve.Should().Be(ExtendedSecurityAlgorithms.Curves.Ed25519);
        parameters.D.Should().BeEquivalentTo(expectedPrivateKey);
        parameters.X.Should().BeEquivalentTo(expectedPublicKey);
    }
    
    [Fact]
    public void ctor_Parameters_WhenEd448KeyPair_ExpectCorrectParameters()
    {
        var keyPair = GenerateEd448KeyPair();
        var expectedPrivateKey = ((Ed448PrivateKeyParameters) keyPair.Private).GetEncoded();
        var expectedPublicKey = ((Ed448PublicKeyParameters) keyPair.Public).GetEncoded();

        var parameters = new EdDsaParameters(keyPair, ExtendedSecurityAlgorithms.Curves.Ed448);

        parameters.Curve.Should().Be(ExtendedSecurityAlgorithms.Curves.Ed448);
        parameters.D.Should().BeEquivalentTo(expectedPrivateKey);
        parameters.X.Should().BeEquivalentTo(expectedPublicKey);
    }

    [Fact]
    public void Validate_WhenBothKeysAreMissing_ExpectCryptographicException()
    {
        var parameters = new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed448);
        Assert.Throws<CryptographicException>(() => parameters.Validate());
    }

    [Fact]
    public void Validate_WhenBothKeysAreEmpty_ExpectCryptographicException()
    {
        var parameters = new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed448) {D = Array.Empty<byte>(), X = Array.Empty<byte>()};
        Assert.Throws<CryptographicException>(() => parameters.Validate());
    }

    [Fact]
    public void Validate_WhenEd25519PrivateKeyIncorrectLength_ExpectCryptographicException()
    {
        var parameters = new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) {D = new byte[1], X = new byte[32]};
        Assert.Throws<CryptographicException>(() => parameters.Validate());
    }

    [Fact]
    public void Validate_WhenEd25519PublicKeyIncorrectLength_ExpectCryptographicException()
    {
        var parameters = new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) {D = new byte[32], X = new byte[1]};
        Assert.Throws<CryptographicException>(() => parameters.Validate());
    }

    [Fact]
    public void Validate_WhenEd448PrivateKeyIncorrectLength_ExpectCryptographicException()
    {
        var parameters = new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed448) {D = new byte[1], X = new byte[57]};
        Assert.Throws<CryptographicException>(() => parameters.Validate());
    }

    [Fact]
    public void Validate_WhenEd448PublicKeyIncorrectLength_ExpectCryptographicException()
    {
        var parameters = new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed448) {D = new byte[57], X = new byte[1]};
        Assert.Throws<CryptographicException>(() => parameters.Validate());
    }

    [Fact]
    public void Validate_WhenEd25519PrivateKeyOnly_ExpectValid()
    {
        var parameters = new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) {D = new byte[32], X = null};
        parameters.Validate();
    }

    [Fact]
    public void Validate_WhenEd25519PublicKeyOnly_ExpectValid()
    {
        var parameters = new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) {D = null, X = new byte[32]};
        parameters.Validate();
    }

    [Fact]
    public void Validate_WhenEd448PrivateKeyOnly_ExpectValid()
    {
        var parameters = new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed448) {D = new byte[57], X = null};
        parameters.Validate();
    }

    [Fact]
    public void Validate_WhenEd448PublicKeyOnly_ExpectValid()
    {
        var parameters = new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed448) {D = null, X = new byte[57]};
        parameters.Validate();
    }

    [Fact]
    public void Validate_WhenEd25519Keys_ExpectValid()
    {
        var parameters = new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) {D = new byte[32], X = new byte[32]};
        parameters.Validate();
    }

    [Fact]
    public void Validate_WhenEd448Keys_ExpectValid()
    {
        var parameters = new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed448) {D = new byte[57], X = new byte[57]};
        parameters.Validate();
    }
    
    private static AsymmetricCipherKeyPair GenerateEd25519KeyPair()
    {
        var keyPairGenerator = new Ed25519KeyPairGenerator();
        keyPairGenerator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        return keyPairGenerator.GenerateKeyPair();
    }
    
    private static AsymmetricCipherKeyPair GenerateEd448KeyPair()
    {
        var keyPairGenerator = new Ed448KeyPairGenerator();
        keyPairGenerator.Init(new Ed448KeyGenerationParameters(new SecureRandom()));
        return keyPairGenerator.GenerateKeyPair();
    }
}