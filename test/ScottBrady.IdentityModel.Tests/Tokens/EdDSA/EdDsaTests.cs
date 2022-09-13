using System;
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
    [Fact]
    public void Create_FromParameters_WhenParametersAreNull_ExpectArgumentNullException()
        => Assert.Throws<ArgumentNullException>(() => EdDsa.Create((EdDsaParameters) null));

    [Fact]
    public void Create_FromParameters_ExpectCorrectParameters()
    {
        var parameters = new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed448) {D = new byte[57]};
        var key = EdDsa.Create(parameters);
        key.Parameters.Should().Be(parameters);
    }
    
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
        alg.Parameters.D.Length.Should().Be(32);
        alg.Parameters.X.Length.Should().Be(32);
    }
    
    [Fact]
    public void Create_WhenEd448_ExpectCorrectKeyParameters()
    {
        var alg = EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed448);
        alg.Parameters.D.Length.Should().Be(57);
        alg.Parameters.X.Length.Should().Be(57);
    }

    [Fact]
    public void Sign_WhenInputNull_ExpectArgumentNullException()
        => Assert.Throws<ArgumentNullException>(() => EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519).Sign(null));

    [Fact]
    public void Verify_WhenInputNull_ExpectArgumentNullException()
        => Assert.Throws<ArgumentNullException>(() => EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519).Verify(null, new byte[32]));
    
    [Fact]
    public void Verify_WhenSignatureNull_ExpectArgumentNullException()
        => Assert.Throws<ArgumentNullException>(() => EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519).Verify(new byte[32], null));
    
    [Fact]
    public void VerifyWithOffsets_WhenSignatureNull_ExpectArgumentNullException()
        => Assert.Throws<ArgumentNullException>(() => 
            EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519).Verify(new byte[32],0,0, null,0,32));    
 
    [Fact]
    public void VerifyWithOffsets_WhenInputNull_ExpectArgumentNullException()
        => Assert.Throws<ArgumentNullException>(() => 
            EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519).Verify(null,0,0, new byte[32],0,32));  
    
    [Fact]
    public void VerifyWithOffsets_WhenInputLengthZero_ExpectArgumentException()
        => Assert.Throws<ArgumentException>(() => 
            EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519).Verify(new byte[32],0,0, new byte[32],0,32));
    
    [Fact]
    public void VerifyWithOffsets_WhenSignatureLengthZero_ExpectArgumentException()
        => Assert.Throws<ArgumentException>(() => 
            EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519).Verify(new byte[32],0,32, new byte[32],0,0));
    
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