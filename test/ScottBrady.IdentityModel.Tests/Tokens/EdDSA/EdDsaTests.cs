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

public class EdDsaTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void Create_WhenNullOrWhitespaceCurve_ExpectArgumentNullException(string curve)
        => Assert.Throws<ArgumentNullException>(() => EdDsa.Create(curve));

    [Fact]
    public void Create_WhenUnsupportedAlgorithm_ExpectNotSupportedException()
        => Assert.Throws<NotSupportedException>(() => EdDsa.Create("P-521"));
    
    [Fact]
    public void Create_WhenEd25519_ExpectCorrectKeyParameters()
    {
        var alg = EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519);
        alg.KeyParameters.Should().BeOfType<Ed25519PrivateKeyParameters>();
    }
    
    [Fact]
    public void Create_WhenEd448_ExpectCorrectKeyParameters()
    {
        var alg = EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed448);
        alg.KeyParameters.Should().BeOfType<Ed448PrivateKeyParameters>();
    }

    [Fact]
    public void CreateFromPrivateKey_WhenNull_ExpectArgumentNullException()
        => Assert.Throws<ArgumentNullException>(() => EdDsa.CreateFromPrivateKey(null, ExtendedSecurityAlgorithms.Curves.Ed25519));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void CreateFromPrivateKey_WhenNullOrWhitespaceCurve_ExpectArgumentNullException(string curve)
        => Assert.Throws<ArgumentNullException>(() => EdDsa.CreateFromPrivateKey(new byte[32], curve));

    [Fact]
    public void CreateFromPrivateKey_WhenUnsupportedCurve_ExpectNotSupportedException()
        => Assert.Throws<NotSupportedException>(() => EdDsa.CreateFromPrivateKey(new byte[32], "P-256"));
    
    [Fact]
    public void CreateFromPrivateKey_WhenEd25519AndKeyLengthIsInvalid_ExpectArgumentException()
    {
        var key = new byte[28];
        RandomNumberGenerator.Fill(key);

        Assert.Throws<ArgumentException>(() => EdDsa.CreateFromPrivateKey(key, ExtendedSecurityAlgorithms.Curves.Ed25519));
    }
    
    [Fact]
    public void CreateFromPrivateKey_WhenEd25519AndKeyIsInvalid_ExpectArgumentException()
    {
        var keyPair = GenerateEd25519KeyPair();
        var key = ((Ed25519PrivateKeyParameters) keyPair.Private).GetEncoded();

        var alg = EdDsa.CreateFromPrivateKey(key, ExtendedSecurityAlgorithms.Curves.Ed25519);
        alg.KeyParameters.Should().BeOfType<Ed25519PrivateKeyParameters>();
    }
    
    [Fact]
    public void CreateFromPrivateKey_WhenEd448AndKeyLengthIsInvalid_ExpectArgumentException()
    {
        var key = new byte[28];
        RandomNumberGenerator.Fill(key);

        Assert.Throws<ArgumentException>(() => EdDsa.CreateFromPrivateKey(key, ExtendedSecurityAlgorithms.Curves.Ed448));
    }
    
    [Fact]
    public void CreateFromPrivateKey_WhenEd448_ExpectCorrectKeyParameters()
    {
        var keyPair = GenerateEd448KeyPair();
        var key = ((Ed448PrivateKeyParameters) keyPair.Private).GetEncoded();

        var alg = EdDsa.CreateFromPrivateKey(key, ExtendedSecurityAlgorithms.Curves.Ed448);
        alg.KeyParameters.Should().BeOfType<Ed448PrivateKeyParameters>();
    }

    [Fact]
    public void CreateFromPublicKey_WhenNull_ExpectArgumentNullException()
        => Assert.Throws<ArgumentNullException>(() => EdDsa.CreateFromPublicKey(null, ExtendedSecurityAlgorithms.Curves.Ed25519));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void CreateFromPublicKey_WhenNullOrWhitespaceCurve_ExpectArgumentNullException(string curve)
        => Assert.Throws<ArgumentNullException>(() => EdDsa.CreateFromPublicKey(new byte[32], curve));

    [Fact]
    public void CreateFromPublicKey_WhenUnsupportedCurve_ExpectNotSupportedException()
        => Assert.Throws<NotSupportedException>(() => EdDsa.CreateFromPublicKey(new byte[32], "P-256"));
    
    [Fact]
    public void CreateFromPublicKey_WhenEd25519AndKeyLengthIsInvalid_ExpectArgumentException()
    {
        var key = new byte[28];
        RandomNumberGenerator.Fill(key);

        Assert.Throws<ArgumentException>(() => EdDsa.CreateFromPublicKey(key, ExtendedSecurityAlgorithms.Curves.Ed25519));
    }
    
    [Fact]
    public void CreateFromPublicKey_WhenEd25519AndKeyIsInvalid_ExpectArgumentException()
    {
        var keyPair = GenerateEd25519KeyPair();
        var key = ((Ed25519PublicKeyParameters) keyPair.Public).GetEncoded();

        var alg = EdDsa.CreateFromPublicKey(key, ExtendedSecurityAlgorithms.Curves.Ed25519);
        alg.KeyParameters.Should().BeOfType<Ed25519PublicKeyParameters>();
    }
    
    [Fact]
    public void CreateFromPublicKey_WhenEd448AndKeyLengthIsInvalid_ExpectArgumentException()
    {
        var key = new byte[28];
        RandomNumberGenerator.Fill(key);

        Assert.Throws<ArgumentException>(() => EdDsa.CreateFromPublicKey(key, ExtendedSecurityAlgorithms.Curves.Ed448));
    }
    
    [Fact]
    public void CreateFromPublicKey_WhenEd448_ExpectCorrectKeyParameters()
    {
        var keyPair = GenerateEd448KeyPair();
        var key = ((Ed448PublicKeyParameters) keyPair.Public).GetEncoded();

        var alg = EdDsa.CreateFromPublicKey(key, ExtendedSecurityAlgorithms.Curves.Ed448);
        alg.KeyParameters.Should().BeOfType<Ed448PublicKeyParameters>();
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