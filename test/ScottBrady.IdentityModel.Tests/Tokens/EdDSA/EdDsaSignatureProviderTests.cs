using System;
using System.Text;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.EdDSA;

public class EdDsaSignatureProviderTests
{
    private readonly byte[] privateKey = Base64UrlEncoder.DecodeBytes("FU1F1QTjYwfB-xkO6aknnBifE_Ywa94U04xpd-XJfBs");
    private readonly byte[] publicKey = Base64UrlEncoder.DecodeBytes("60mR98SQlHUSeLeIu7TeJBTLRG10qlcDLU4AJjQdqMQ");
    private readonly byte[] plaintext = Encoding.UTF8.GetBytes("eyJraWQiOiIxMjMiLCJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJhdWQiOiJ5b3UiLCJzdWIiOiJib2IiLCJpc3MiOiJtZSIsImV4cCI6MTU5MDg0MTg4N30");
    private readonly byte[] validSignature = Base64UrlEncoder.DecodeBytes("OyBxBr344Ny-0vRCeEMLSnuEO1IecybvJBivrjum4d-dgN5WLnEAGAO43MlZeRGn1F3fRXO_xlYot68PtDuiAA");
 
    [Fact]
    public void ctor_WithPrivateKey_ExpectPropertiesSet()
    {
        var securityKey = new EdDsaSecurityKey(EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) { D = privateKey }));
        var algorithm = ExtendedSecurityAlgorithms.EdDsa;

        var provider = new EdDsaSignatureProvider(securityKey, algorithm);

        provider.Key.Should().Be(securityKey);
        provider.Algorithm.Should().Be(algorithm);
        provider.WillCreateSignatures.Should().BeTrue();
    }
    [Fact]
    public void ctor_WithPublicKey_ExpectPropertiesSet()
    {
        var securityKey = new EdDsaSecurityKey(EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) { X = publicKey }));
        var algorithm = ExtendedSecurityAlgorithms.EdDsa;

        var provider = new EdDsaSignatureProvider(securityKey, algorithm);

        provider.Key.Should().Be(securityKey);
        provider.Algorithm.Should().Be(algorithm);
        provider.WillCreateSignatures.Should().BeFalse();
    }
    
    [Fact]
    public void Dispose_ExpectNoException()
    {
        new EdDsaSignatureProvider(new EdDsaSecurityKey(EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519)), ExtendedSecurityAlgorithms.EdDsa).Dispose();
    }

    [Fact]
    public void Sign_WhenSigningWithEd25519Curve_ExpectCorrectSignature()
    {
        var edDsaSecurityKey = new EdDsaSecurityKey(EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) { D = privateKey }));
        var signatureProvider = new EdDsaSignatureProvider(edDsaSecurityKey, ExtendedSecurityAlgorithms.EdDsa);

        var signature = signatureProvider.Sign(plaintext);

        signature.Should().BeEquivalentTo(validSignature);
    }

    [Fact]
    public void Verify_WhenJwtSignedWithEd25519Curve_ExpectTrue()
    {
        var edDsaSecurityKey = new EdDsaSecurityKey(EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) { X = publicKey }));
        var signatureProvider = new EdDsaSignatureProvider(edDsaSecurityKey, ExtendedSecurityAlgorithms.EdDsa);
        
        var isValidSignature = signatureProvider.Verify(plaintext, validSignature);

        isValidSignature.Should().BeTrue();
    }

    [Fact]
    public void Verify_WithOffsets_WhenJwtSignedWithEd25519Curve_ExpectTrue()
    {
        var edDsaSecurityKey = new EdDsaSecurityKey(EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) { X = publicKey }));
        var signatureProvider = new EdDsaSignatureProvider(edDsaSecurityKey, ExtendedSecurityAlgorithms.EdDsa);

        var isValidSignature = signatureProvider.Verify(plaintext, 0, plaintext.Length, validSignature, 0, validSignature.Length);

        isValidSignature.Should().BeTrue();
    }

    [Fact]
    public void Sign_WithSpan_WhenSigningWithEd25519Curve_ExpectCorrectSignature()
    {
        var edDsaSecurityKey = new EdDsaSecurityKey(EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) { D = privateKey }));
        var signatureProvider = new EdDsaSignatureProvider(edDsaSecurityKey, ExtendedSecurityAlgorithms.EdDsa);

        Span<byte> signature = stackalloc byte[64];
        var isSuccess = signatureProvider.Sign(plaintext.AsSpan(), signature, out var bytesWritten);

        isSuccess.Should().BeTrue();
        signature.ToArray().Should().BeEquivalentTo(validSignature);
        bytesWritten.Should().Be(64);
    }

    [Fact]
    public void Sign_WithOffset_WhenSigningWithEd25519Curve_ExpectCorrectSignature()
    {
        var edDsaSecurityKey = new EdDsaSecurityKey(EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) { D = privateKey }));
        var signatureProvider = new EdDsaSignatureProvider(edDsaSecurityKey, ExtendedSecurityAlgorithms.EdDsa);

        var input = new byte[plaintext.Length + 1];
        Buffer.BlockCopy(plaintext, 0, input, 1, plaintext.Length);
        
        var signature = signatureProvider.Sign(input, 1, plaintext.Length);

        signature.Should().BeEquivalentTo(validSignature);
    }
}