using System;
using System.Security.Cryptography;
using FluentAssertions;
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
    public void Validate_WhenEd25519SigningKey_ExpectValid()
    {
        var parameters = new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) {D = new byte[32 * 2], X = null};
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
    public void Validate_WhenEd448SigningKey_ExpectValid()
    {
        var parameters = new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed448) {D = new byte[57 * 2], X = null};
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
}