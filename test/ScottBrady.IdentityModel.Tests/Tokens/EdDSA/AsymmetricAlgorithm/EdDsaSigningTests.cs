using System;
using System.Security.Cryptography;
using FluentAssertions;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.EdDSA.AsymmetricAlgorithm;

public class EdDsaSigningTests : EdDsaTestBase
{
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
    
    [Theory]
    [InlineData(ExtendedSecurityAlgorithms.Curves.Ed25519)]
    [InlineData(ExtendedSecurityAlgorithms.Curves.Ed448)]
    public void SignAndVerify_ExpectValidSignature(string curve)
    {
        var key = EdDsa.Create(curve);
        var input = RandomNumberGenerator.GetBytes(RandomNumberGenerator.GetInt32(1, 3072));
        
        var signature = key.Sign(input);
        key.Verify(input, signature).Should().BeTrue();
    }
}